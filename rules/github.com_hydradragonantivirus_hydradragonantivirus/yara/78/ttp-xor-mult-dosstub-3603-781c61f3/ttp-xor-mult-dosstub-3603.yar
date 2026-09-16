rule TTP_XOR_MULT_DOSStub_3603 {
  strings:
    $key_3603 = { 62 6b [2] 16 73 [2] 51 71 [2] 16 60 [2] 58 6c [2] 54 66 [2] 43 6d [2] 58 23 [2] 65 }

  condition:
    any of them
}