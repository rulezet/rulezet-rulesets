rule TTP_XOR_MULT_DOSStub_2c53 {
  strings:
    $key_2c53 = { 78 3b [2] 0c 23 [2] 4b 21 [2] 0c 30 [2] 42 3c [2] 4e 36 [2] 59 3d [2] 42 73 [2] 7f }

  condition:
    any of them
}