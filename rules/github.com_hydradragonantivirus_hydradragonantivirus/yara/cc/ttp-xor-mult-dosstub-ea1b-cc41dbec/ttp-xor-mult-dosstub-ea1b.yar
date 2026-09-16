rule TTP_XOR_MULT_DOSStub_ea1b {
  strings:
    $key_ea1b = { be 73 [2] ca 6b [2] 8d 69 [2] ca 78 [2] 84 74 [2] 88 7e [2] 9f 75 [2] 84 3b [2] b9 }

  condition:
    any of them
}