rule TTP_XOR_MULT_DOSStub_ea71 {
  strings:
    $key_ea71 = { be 19 [2] ca 01 [2] 8d 03 [2] ca 12 [2] 84 1e [2] 88 14 [2] 9f 1f [2] 84 51 [2] b9 }

  condition:
    any of them
}