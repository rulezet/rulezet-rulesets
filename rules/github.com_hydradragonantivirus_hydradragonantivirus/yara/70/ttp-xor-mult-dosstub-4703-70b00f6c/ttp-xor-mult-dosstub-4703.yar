rule TTP_XOR_MULT_DOSStub_4703 {
  strings:
    $key_4703 = { 13 6b [2] 67 73 [2] 20 71 [2] 67 60 [2] 29 6c [2] 25 66 [2] 32 6d [2] 29 23 [2] 14 }

  condition:
    any of them
}