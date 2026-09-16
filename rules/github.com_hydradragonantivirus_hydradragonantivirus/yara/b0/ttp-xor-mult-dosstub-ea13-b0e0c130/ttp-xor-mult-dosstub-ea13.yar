rule TTP_XOR_MULT_DOSStub_ea13 {
  strings:
    $key_ea13 = { be 7b [2] ca 63 [2] 8d 61 [2] ca 70 [2] 84 7c [2] 88 76 [2] 9f 7d [2] 84 33 [2] b9 }

  condition:
    any of them
}