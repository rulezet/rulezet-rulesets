rule TTP_XOR_MULT_DOSStub_7a3f {
  strings:
    $key_7a3f = { 2e 57 [2] 5a 4f [2] 1d 4d [2] 5a 5c [2] 14 50 [2] 18 5a [2] 0f 51 [2] 14 1f [2] 29 }

  condition:
    any of them
}