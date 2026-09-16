rule TTP_XOR_MULT_DOSStub_ea45 {
  strings:
    $key_ea45 = { be 2d [2] ca 35 [2] 8d 37 [2] ca 26 [2] 84 2a [2] 88 20 [2] 9f 2b [2] 84 65 [2] b9 }

  condition:
    any of them
}