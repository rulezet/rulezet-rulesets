rule TTP_XOR_MULT_DOSStub_367f {
  strings:
    $key_367f = { 62 17 [2] 16 0f [2] 51 0d [2] 16 1c [2] 58 10 [2] 54 1a [2] 43 11 [2] 58 5f [2] 65 }

  condition:
    any of them
}