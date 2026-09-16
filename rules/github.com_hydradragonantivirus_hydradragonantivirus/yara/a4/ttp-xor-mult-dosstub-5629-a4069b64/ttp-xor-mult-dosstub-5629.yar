rule TTP_XOR_MULT_DOSStub_5629 {
  strings:
    $key_5629 = { 02 41 [2] 76 59 [2] 31 5b [2] 76 4a [2] 38 46 [2] 34 4c [2] 23 47 [2] 38 09 [2] 05 }

  condition:
    any of them
}