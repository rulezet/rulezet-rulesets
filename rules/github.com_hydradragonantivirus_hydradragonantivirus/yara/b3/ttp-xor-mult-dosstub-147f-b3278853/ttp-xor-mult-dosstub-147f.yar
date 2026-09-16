rule TTP_XOR_MULT_DOSStub_147f {
  strings:
    $key_147f = { 40 17 [2] 34 0f [2] 73 0d [2] 34 1c [2] 7a 10 [2] 76 1a [2] 61 11 [2] 7a 5f [2] 47 }

  condition:
    any of them
}