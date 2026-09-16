rule suspicious_version_ren: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 3

  strings:
    $magic = "%PDF"
    $ver   = /%PDF-1.\d{1}/

  condition:
    $magic in (0..1024) and not $ver
}