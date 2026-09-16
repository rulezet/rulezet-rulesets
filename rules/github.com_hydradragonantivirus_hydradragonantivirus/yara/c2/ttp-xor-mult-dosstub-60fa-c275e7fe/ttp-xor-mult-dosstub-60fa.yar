rule TTP_XOR_MULT_DOSStub_60fa {
  strings:
    $key_60fa = { 34 92 [2] 40 8a [2] 07 88 [2] 40 99 [2] 0e 95 [2] 02 9f [2] 15 94 [2] 0e da [2] 33 }

  condition:
    any of them
}