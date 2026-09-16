rule TTP_XOR_MULT_DOSStub_ea7c {
  strings:
    $key_ea7c = { be 14 [2] ca 0c [2] 8d 0e [2] ca 1f [2] 84 13 [2] 88 19 [2] 9f 12 [2] 84 5c [2] b9 }

  condition:
    any of them
}