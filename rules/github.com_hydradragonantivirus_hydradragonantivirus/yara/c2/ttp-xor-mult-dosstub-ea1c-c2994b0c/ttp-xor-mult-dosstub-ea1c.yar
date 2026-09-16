rule TTP_XOR_MULT_DOSStub_ea1c {
  strings:
    $key_ea1c = { be 74 [2] ca 6c [2] 8d 6e [2] ca 7f [2] 84 73 [2] 88 79 [2] 9f 72 [2] 84 3c [2] b9 }

  condition:
    any of them
}