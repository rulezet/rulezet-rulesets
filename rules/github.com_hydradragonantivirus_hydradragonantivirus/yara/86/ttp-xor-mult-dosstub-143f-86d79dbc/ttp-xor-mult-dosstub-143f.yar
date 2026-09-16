rule TTP_XOR_MULT_DOSStub_143f {
  strings:
    $key_143f = { 40 57 [2] 34 4f [2] 73 4d [2] 34 5c [2] 7a 50 [2] 76 5a [2] 61 51 [2] 7a 1f [2] 47 }

  condition:
    any of them
}