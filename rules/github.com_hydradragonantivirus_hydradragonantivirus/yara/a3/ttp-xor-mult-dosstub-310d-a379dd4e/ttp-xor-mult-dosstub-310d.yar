rule TTP_XOR_MULT_DOSStub_310d {
  strings:
    $key_310d = { 65 65 [2] 11 7d [2] 56 7f [2] 11 6e [2] 5f 62 [2] 53 68 [2] 44 63 [2] 5f 2d [2] 62 }

  condition:
    any of them
}