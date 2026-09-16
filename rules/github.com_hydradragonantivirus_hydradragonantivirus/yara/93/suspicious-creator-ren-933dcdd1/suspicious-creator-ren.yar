rule suspicious_creator_ren: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 3

  strings:
    $magic  = "%PDF"
    $header = /%PDF-1\.(3|4|6)/

    $creator0 = "yen vaw"
    $creator1 = "Scribus"
    $creator2 = "Viraciregavi"

  condition:
    $magic in (0..1024) and $header and 1 of ($creator*)
}