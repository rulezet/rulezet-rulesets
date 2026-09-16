rule TTP_XOR_MULT_DOSStub_40e5 {
  strings:
    $key_40e5 = { 14 8d [2] 60 95 [2] 27 97 [2] 60 86 [2] 2e 8a [2] 22 80 [2] 35 8b [2] 2e c5 [2] 13 }

  condition:
    any of them
}