rule TTP_XOR_MULT_DOSStub_52fa {
  strings:
    $key_52fa = { 06 92 [2] 72 8a [2] 35 88 [2] 72 99 [2] 3c 95 [2] 30 9f [2] 27 94 [2] 3c da [2] 01 }

  condition:
    any of them
}