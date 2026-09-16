rule TTP_XOR_MULT_DOSStub_2c03 {
  strings:
    $key_2c03 = { 78 6b [2] 0c 73 [2] 4b 71 [2] 0c 60 [2] 42 6c [2] 4e 66 [2] 59 6d [2] 42 23 [2] 7f }

  condition:
    any of them
}