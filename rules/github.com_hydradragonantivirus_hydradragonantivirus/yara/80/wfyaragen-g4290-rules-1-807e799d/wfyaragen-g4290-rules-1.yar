rule WFYARAGEN_G4290_rules_1 {
  meta:
    description = "Matches a URL-encoded string with magic bytes fitting a zlib stream"

  strings:
    $re = /^x%(01|25|9C|DA|5E)[A-Za-z\d.\-+_]+$/ nocase

  condition:
    $re
}