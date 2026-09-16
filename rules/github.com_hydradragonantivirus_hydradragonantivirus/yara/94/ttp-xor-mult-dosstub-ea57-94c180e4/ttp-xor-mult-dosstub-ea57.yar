rule TTP_XOR_MULT_DOSStub_ea57 {
  strings:
    $key_ea57 = { be 3f [2] ca 27 [2] 8d 25 [2] ca 34 [2] 84 38 [2] 88 32 [2] 9f 39 [2] 84 77 [2] b9 }

  condition:
    any of them
}