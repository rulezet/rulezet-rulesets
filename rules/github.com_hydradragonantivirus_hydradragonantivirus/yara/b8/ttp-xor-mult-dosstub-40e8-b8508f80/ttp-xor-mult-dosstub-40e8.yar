rule TTP_XOR_MULT_DOSStub_40e8 {
  strings:
    $key_40e8 = { 14 80 [2] 60 98 [2] 27 9a [2] 60 8b [2] 2e 87 [2] 22 8d [2] 35 86 [2] 2e c8 [2] 13 }

  condition:
    any of them
}