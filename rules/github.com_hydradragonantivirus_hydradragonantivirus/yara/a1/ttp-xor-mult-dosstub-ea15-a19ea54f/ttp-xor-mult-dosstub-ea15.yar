rule TTP_XOR_MULT_DOSStub_ea15 {
  strings:
    $key_ea15 = { be 7d [2] ca 65 [2] 8d 67 [2] ca 76 [2] 84 7a [2] 88 70 [2] 9f 7b [2] 84 35 [2] b9 }

  condition:
    any of them
}