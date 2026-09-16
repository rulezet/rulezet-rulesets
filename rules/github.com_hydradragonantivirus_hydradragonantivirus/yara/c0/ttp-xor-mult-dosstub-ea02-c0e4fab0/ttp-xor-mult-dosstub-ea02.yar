rule TTP_XOR_MULT_DOSStub_ea02 {
  strings:
    $key_ea02 = { be 6a [2] ca 72 [2] 8d 70 [2] ca 61 [2] 84 6d [2] 88 67 [2] 9f 6c [2] 84 22 [2] b9 }

  condition:
    any of them
}