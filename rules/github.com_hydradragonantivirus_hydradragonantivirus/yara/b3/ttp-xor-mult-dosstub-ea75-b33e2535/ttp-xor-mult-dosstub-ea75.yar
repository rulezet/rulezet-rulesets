rule TTP_XOR_MULT_DOSStub_ea75 {
  strings:
    $key_ea75 = { be 1d [2] ca 05 [2] 8d 07 [2] ca 16 [2] 84 1a [2] 88 10 [2] 9f 1b [2] 84 55 [2] b9 }

  condition:
    any of them
}