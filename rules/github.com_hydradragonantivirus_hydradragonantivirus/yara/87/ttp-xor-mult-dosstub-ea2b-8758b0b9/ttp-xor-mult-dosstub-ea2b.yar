rule TTP_XOR_MULT_DOSStub_ea2b {
  strings:
    $key_ea2b = { be 43 [2] ca 5b [2] 8d 59 [2] ca 48 [2] 84 44 [2] 88 4e [2] 9f 45 [2] 84 0b [2] b9 }

  condition:
    any of them
}