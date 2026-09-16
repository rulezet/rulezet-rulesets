rule TTP_XOR_MULT_DOSStub_5a0a {
  strings:
    $key_5a0a = { 0e 62 [2] 7a 7a [2] 3d 78 [2] 7a 69 [2] 34 65 [2] 38 6f [2] 2f 64 [2] 34 2a [2] 09 }

  condition:
    any of them
}