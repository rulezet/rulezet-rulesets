rule TTP_XOR_MULT_DOSStub_ea43 {
  strings:
    $key_ea43 = { be 2b [2] ca 33 [2] 8d 31 [2] ca 20 [2] 84 2c [2] 88 26 [2] 9f 2d [2] 84 63 [2] b9 }

  condition:
    any of them
}