rule TTP_XOR_MULT_DOSStub_4053 {
  strings:
    $key_4053 = { 14 3b [2] 60 23 [2] 27 21 [2] 60 30 [2] 2e 3c [2] 22 36 [2] 35 3d [2] 2e 73 [2] 13 }

  condition:
    any of them
}