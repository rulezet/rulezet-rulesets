rule TTP_XOR_MULT_DOSStub_7c03 {
  strings:
    $key_7c03 = { 28 6b [2] 5c 73 [2] 1b 71 [2] 5c 60 [2] 12 6c [2] 1e 66 [2] 09 6d [2] 12 23 [2] 2f }

  condition:
    any of them
}