rule TTP_XOR_MULT_DOSStub_710a {
  strings:
    $key_710a = { 25 62 [2] 51 7a [2] 16 78 [2] 51 69 [2] 1f 65 [2] 13 6f [2] 04 64 [2] 1f 2a [2] 22 }

  condition:
    any of them
}