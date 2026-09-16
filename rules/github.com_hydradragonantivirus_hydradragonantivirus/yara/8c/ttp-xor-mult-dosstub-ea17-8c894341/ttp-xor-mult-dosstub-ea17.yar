rule TTP_XOR_MULT_DOSStub_ea17 {
  strings:
    $key_ea17 = { be 7f [2] ca 67 [2] 8d 65 [2] ca 74 [2] 84 78 [2] 88 72 [2] 9f 79 [2] 84 37 [2] b9 }

  condition:
    any of them
}