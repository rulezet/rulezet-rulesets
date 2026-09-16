rule TTP_XOR_MULT_DOSStub_180a {
  strings:
    $key_180a = { 4c 62 [2] 38 7a [2] 7f 78 [2] 38 69 [2] 76 65 [2] 7a 6f [2] 6d 64 [2] 76 2a [2] 4b }

  condition:
    any of them
}