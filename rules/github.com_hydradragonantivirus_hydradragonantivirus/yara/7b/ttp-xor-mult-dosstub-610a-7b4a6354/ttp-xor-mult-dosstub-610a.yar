rule TTP_XOR_MULT_DOSStub_610a {
  strings:
    $key_610a = { 35 62 [2] 41 7a [2] 06 78 [2] 41 69 [2] 0f 65 [2] 03 6f [2] 14 64 [2] 0f 2a [2] 32 }

  condition:
    any of them
}