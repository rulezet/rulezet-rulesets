rule TTP_XOR_MULT_DOSStub_ea1d {
  strings:
    $key_ea1d = { be 75 [2] ca 6d [2] 8d 6f [2] ca 7e [2] 84 72 [2] 88 78 [2] 9f 73 [2] 84 3d [2] b9 }

  condition:
    any of them
}