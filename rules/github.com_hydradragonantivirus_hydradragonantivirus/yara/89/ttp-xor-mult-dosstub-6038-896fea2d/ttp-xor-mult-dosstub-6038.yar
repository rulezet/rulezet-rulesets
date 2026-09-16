rule TTP_XOR_MULT_DOSStub_6038 {
  strings:
    $key_6038 = { 34 50 [2] 40 48 [2] 07 4a [2] 40 5b [2] 0e 57 [2] 02 5d [2] 15 56 [2] 0e 18 [2] 33 }

  condition:
    any of them
}