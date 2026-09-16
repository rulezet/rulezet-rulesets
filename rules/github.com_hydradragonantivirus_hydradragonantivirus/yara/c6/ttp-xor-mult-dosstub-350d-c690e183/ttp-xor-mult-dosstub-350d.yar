rule TTP_XOR_MULT_DOSStub_350d {
  strings:
    $key_350d = { 61 65 [2] 15 7d [2] 52 7f [2] 15 6e [2] 5b 62 [2] 57 68 [2] 40 63 [2] 5b 2d [2] 66 }

  condition:
    any of them
}