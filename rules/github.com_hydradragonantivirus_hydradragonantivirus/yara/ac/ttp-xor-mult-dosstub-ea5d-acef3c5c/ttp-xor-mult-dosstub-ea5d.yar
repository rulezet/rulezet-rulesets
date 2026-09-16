rule TTP_XOR_MULT_DOSStub_ea5d {
  strings:
    $key_ea5d = { be 35 [2] ca 2d [2] 8d 2f [2] ca 3e [2] 84 32 [2] 88 38 [2] 9f 33 [2] 84 7d [2] b9 }

  condition:
    any of them
}