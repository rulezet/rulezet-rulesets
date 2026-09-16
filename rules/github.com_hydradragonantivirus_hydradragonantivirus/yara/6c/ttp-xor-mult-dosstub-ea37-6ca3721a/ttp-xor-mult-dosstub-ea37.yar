rule TTP_XOR_MULT_DOSStub_ea37 {
  strings:
    $key_ea37 = { be 5f [2] ca 47 [2] 8d 45 [2] ca 54 [2] 84 58 [2] 88 52 [2] 9f 59 [2] 84 17 [2] b9 }

  condition:
    any of them
}