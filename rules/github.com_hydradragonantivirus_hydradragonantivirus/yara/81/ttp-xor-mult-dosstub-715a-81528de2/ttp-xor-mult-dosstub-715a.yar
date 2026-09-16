rule TTP_XOR_MULT_DOSStub_715a {
  strings:
    $key_715a = { 25 32 [2] 51 2a [2] 16 28 [2] 51 39 [2] 1f 35 [2] 13 3f [2] 04 34 [2] 1f 7a [2] 22 }

  condition:
    any of them
}