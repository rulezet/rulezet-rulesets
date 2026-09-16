rule TTP_XOR_MULT_DOSStub_4253 {
  strings:
    $key_4253 = { 16 3b [2] 62 23 [2] 25 21 [2] 62 30 [2] 2c 3c [2] 20 36 [2] 37 3d [2] 2c 73 [2] 11 }

  condition:
    any of them
}