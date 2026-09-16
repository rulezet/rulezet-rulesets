rule TTP_XOR_MULT_DOSStub_ea55 {
  strings:
    $key_ea55 = { be 3d [2] ca 25 [2] 8d 27 [2] ca 36 [2] 84 3a [2] 88 30 [2] 9f 3b [2] 84 75 [2] b9 }

  condition:
    any of them
}