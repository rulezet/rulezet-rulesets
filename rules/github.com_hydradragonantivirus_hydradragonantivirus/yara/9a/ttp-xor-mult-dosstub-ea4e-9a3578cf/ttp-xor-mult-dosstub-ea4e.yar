rule TTP_XOR_MULT_DOSStub_ea4e {
  strings:
    $key_ea4e = { be 26 [2] ca 3e [2] 8d 3c [2] ca 2d [2] 84 21 [2] 88 2b [2] 9f 20 [2] 84 6e [2] b9 }

  condition:
    any of them
}