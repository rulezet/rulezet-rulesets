rule TTP_XOR_MULT_DOSStub_ea07 {
  strings:
    $key_ea07 = { be 6f [2] ca 77 [2] 8d 75 [2] ca 64 [2] 84 68 [2] 88 62 [2] 9f 69 [2] 84 27 [2] b9 }

  condition:
    any of them
}