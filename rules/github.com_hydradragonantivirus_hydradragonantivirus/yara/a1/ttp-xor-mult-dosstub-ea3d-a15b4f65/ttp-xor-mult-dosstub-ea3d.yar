rule TTP_XOR_MULT_DOSStub_ea3d {
  strings:
    $key_ea3d = { be 55 [2] ca 4d [2] 8d 4f [2] ca 5e [2] 84 52 [2] 88 58 [2] 9f 53 [2] 84 1d [2] b9 }

  condition:
    any of them
}