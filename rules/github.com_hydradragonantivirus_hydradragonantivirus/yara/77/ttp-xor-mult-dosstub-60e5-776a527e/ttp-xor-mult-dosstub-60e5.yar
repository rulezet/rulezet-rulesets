rule TTP_XOR_MULT_DOSStub_60e5 {
  strings:
    $key_60e5 = { 34 8d [2] 40 95 [2] 07 97 [2] 40 86 [2] 0e 8a [2] 02 80 [2] 15 8b [2] 0e c5 [2] 33 }

  condition:
    any of them
}