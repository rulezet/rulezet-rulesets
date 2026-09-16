rule TTP_XOR_MULT_DOSStub_ea73 {
  strings:
    $key_ea73 = { be 1b [2] ca 03 [2] 8d 01 [2] ca 10 [2] 84 1c [2] 88 16 [2] 9f 1d [2] 84 53 [2] b9 }

  condition:
    any of them
}