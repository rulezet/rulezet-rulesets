rule TTP_XOR_MULT_DOSStub_ea06 {
  strings:
    $key_ea06 = { be 6e [2] ca 76 [2] 8d 74 [2] ca 65 [2] 84 69 [2] 88 63 [2] 9f 68 [2] 84 26 [2] b9 }

  condition:
    any of them
}