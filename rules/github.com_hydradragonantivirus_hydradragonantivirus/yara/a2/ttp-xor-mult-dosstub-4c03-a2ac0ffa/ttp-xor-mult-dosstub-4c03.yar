rule TTP_XOR_MULT_DOSStub_4c03 {
  strings:
    $key_4c03 = { 18 6b [2] 6c 73 [2] 2b 71 [2] 6c 60 [2] 22 6c [2] 2e 66 [2] 39 6d [2] 22 23 [2] 1f }

  condition:
    any of them
}