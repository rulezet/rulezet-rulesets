rule TTP_XOR_MULT_DOSStub_2503 {
  strings:
    $key_2503 = { 71 6b [2] 05 73 [2] 42 71 [2] 05 60 [2] 4b 6c [2] 47 66 [2] 50 6d [2] 4b 23 [2] 76 }

  condition:
    any of them
}