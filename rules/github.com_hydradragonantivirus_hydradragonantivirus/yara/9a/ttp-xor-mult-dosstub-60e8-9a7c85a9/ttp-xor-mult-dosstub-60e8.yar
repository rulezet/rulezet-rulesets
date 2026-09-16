rule TTP_XOR_MULT_DOSStub_60e8 {
  strings:
    $key_60e8 = { 34 80 [2] 40 98 [2] 07 9a [2] 40 8b [2] 0e 87 [2] 02 8d [2] 15 86 [2] 0e c8 [2] 33 }

  condition:
    any of them
}