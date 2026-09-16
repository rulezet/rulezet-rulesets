rule TTP_XOR_MULT_DOSStub_ea6d {
  strings:
    $key_ea6d = { be 05 [2] ca 1d [2] 8d 1f [2] ca 0e [2] 84 02 [2] 88 08 [2] 9f 03 [2] 84 4d [2] b9 }

  condition:
    any of them
}