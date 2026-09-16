rule TTP_XOR_MULT_DOSStub_6c03 {
  strings:
    $key_6c03 = { 38 6b [2] 4c 73 [2] 0b 71 [2] 4c 60 [2] 02 6c [2] 0e 66 [2] 19 6d [2] 02 23 [2] 3f }

  condition:
    any of them
}