rule TTP_XOR_MULT_DOSStub_7d0d {
  strings:
    $key_7d0d = { 29 65 [2] 5d 7d [2] 1a 7f [2] 5d 6e [2] 13 62 [2] 1f 68 [2] 08 63 [2] 13 2d [2] 2e }

  condition:
    any of them
}