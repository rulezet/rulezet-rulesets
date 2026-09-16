rule TTP_XOR_MULT_DOSStub_ea12 {
  strings:
    $key_ea12 = { be 7a [2] ca 62 [2] 8d 60 [2] ca 71 [2] 84 7d [2] 88 77 [2] 9f 7c [2] 84 32 [2] b9 }

  condition:
    any of them
}