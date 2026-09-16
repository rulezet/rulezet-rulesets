rule TTP_XOR_MULT_DOSStub_3103 {
  strings:
    $key_3103 = { 65 6b [2] 11 73 [2] 56 71 [2] 11 60 [2] 5f 6c [2] 53 66 [2] 44 6d [2] 5f 23 [2] 62 }

  condition:
    any of them
}