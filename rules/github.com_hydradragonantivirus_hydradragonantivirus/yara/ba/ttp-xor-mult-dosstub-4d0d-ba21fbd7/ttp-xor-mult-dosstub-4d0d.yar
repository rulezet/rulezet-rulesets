rule TTP_XOR_MULT_DOSStub_4d0d {
  strings:
    $key_4d0d = { 19 65 [2] 6d 7d [2] 2a 7f [2] 6d 6e [2] 23 62 [2] 2f 68 [2] 38 63 [2] 23 2d [2] 1e }

  condition:
    any of them
}