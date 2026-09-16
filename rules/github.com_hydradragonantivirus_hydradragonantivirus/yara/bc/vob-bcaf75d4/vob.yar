rule vob: VOB {
  meta:
    author = "Joan Bono"

  strings:
    $a = { FF FF FF 5D 00 00 00 02 00 01 00 00 00 FC FF 35 }

  condition:
    $a at 0
}