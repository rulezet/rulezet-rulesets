rule TTP_XOR_MULT_DOSStub_ea50 {
  strings:
    $key_ea50 = { be 38 [2] ca 20 [2] 8d 22 [2] ca 33 [2] 84 3f [2] 88 35 [2] 9f 3e [2] 84 70 [2] b9 }

  condition:
    any of them
}