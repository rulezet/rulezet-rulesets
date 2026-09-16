rule TTP_XOR_MULT_DOSStub_1c03 {
  strings:
    $key_1c03 = { 48 6b [2] 3c 73 [2] 7b 71 [2] 3c 60 [2] 72 6c [2] 7e 66 [2] 69 6d [2] 72 23 [2] 4f }

  condition:
    any of them
}