rule TTP_XOR_MULT_DOSStub_4203 {
  strings:
    $key_4203 = { 16 6b [2] 62 73 [2] 25 71 [2] 62 60 [2] 2c 6c [2] 20 66 [2] 37 6d [2] 2c 23 [2] 11 }

  condition:
    any of them
}