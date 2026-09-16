rule TTP_XOR_MULT_DOSStub_0503 {
  strings:
    $key_0503 = { 51 6b [2] 25 73 [2] 62 71 [2] 25 60 [2] 6b 6c [2] 67 66 [2] 70 6d [2] 6b 23 [2] 56 }

  condition:
    any of them
}