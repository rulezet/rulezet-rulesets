rule TTP_XOR_MULT_DOSStub_ea28 {
  strings:
    $key_ea28 = { be 40 [2] ca 58 [2] 8d 5a [2] ca 4b [2] 84 47 [2] 88 4d [2] 9f 46 [2] 84 08 [2] b9 }

  condition:
    any of them
}