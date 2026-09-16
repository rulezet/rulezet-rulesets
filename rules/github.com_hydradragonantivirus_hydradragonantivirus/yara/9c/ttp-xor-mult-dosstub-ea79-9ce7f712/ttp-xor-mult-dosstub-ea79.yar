rule TTP_XOR_MULT_DOSStub_ea79 {
  strings:
    $key_ea79 = { be 11 [2] ca 09 [2] 8d 0b [2] ca 1a [2] 84 16 [2] 88 1c [2] 9f 17 [2] 84 59 [2] b9 }

  condition:
    any of them
}