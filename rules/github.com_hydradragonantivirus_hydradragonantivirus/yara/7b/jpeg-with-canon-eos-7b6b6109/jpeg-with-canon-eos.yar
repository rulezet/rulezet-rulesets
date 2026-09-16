rule jpeg_with_Canon_EOS: JPEG {
  meta:
    author = "Jaume Martin"

  strings:
    $a = { FF D8 FF E2 ?? ?? 53 50 49 46 46 00 }

  condition:
    $a at 0
}