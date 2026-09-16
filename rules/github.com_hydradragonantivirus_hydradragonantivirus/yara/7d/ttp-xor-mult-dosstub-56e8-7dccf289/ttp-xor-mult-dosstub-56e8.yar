rule TTP_XOR_MULT_DOSStub_56e8 {
  strings:
    $key_56e8 = { 02 80 [2] 76 98 [2] 31 9a [2] 76 8b [2] 38 87 [2] 34 8d [2] 23 86 [2] 38 c8 [2] 05 }

  condition:
    any of them
}