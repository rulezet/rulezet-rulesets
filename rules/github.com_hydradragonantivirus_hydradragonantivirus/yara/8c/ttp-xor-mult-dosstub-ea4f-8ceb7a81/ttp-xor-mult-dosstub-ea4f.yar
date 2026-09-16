rule TTP_XOR_MULT_DOSStub_ea4f {
  strings:
    $key_ea4f = { be 27 [2] ca 3f [2] 8d 3d [2] ca 2c [2] 84 20 [2] 88 2a [2] 9f 21 [2] 84 6f [2] b9 }

  condition:
    any of them
}