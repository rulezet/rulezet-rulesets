rule suspicious_producer_ren: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 2

  strings:
    $magic  = "%PDF"
    $header = /%PDF-1\.(3|4|6)/

    $producer0 = /Producer \(Scribus PDF Library/
    $producer1 = "Notepad"

  condition:
    $magic in (0..1024) and $header and 1 of ($producer*)
}