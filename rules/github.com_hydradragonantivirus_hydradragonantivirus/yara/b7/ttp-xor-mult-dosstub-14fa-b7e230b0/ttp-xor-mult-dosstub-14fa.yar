rule TTP_XOR_MULT_DOSStub_14fa {
  strings:
    $key_14fa = { 40 92 [2] 34 8a [2] 73 88 [2] 34 99 [2] 7a 95 [2] 76 9f [2] 61 94 [2] 7a da [2] 47 }

  condition:
    any of them
}