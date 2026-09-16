rule TTP_XOR_MULT_DOSStub_ea3c {
  strings:
    $key_ea3c = { be 54 [2] ca 4c [2] 8d 4e [2] ca 5f [2] 84 53 [2] 88 59 [2] 9f 52 [2] 84 1c [2] b9 }

  condition:
    any of them
}