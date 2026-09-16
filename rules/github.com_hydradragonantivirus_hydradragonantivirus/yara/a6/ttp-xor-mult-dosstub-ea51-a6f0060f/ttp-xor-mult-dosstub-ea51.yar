rule TTP_XOR_MULT_DOSStub_ea51 {
  strings:
    $key_ea51 = { be 39 [2] ca 21 [2] 8d 23 [2] ca 32 [2] 84 3e [2] 88 34 [2] 9f 3f [2] 84 71 [2] b9 }

  condition:
    any of them
}