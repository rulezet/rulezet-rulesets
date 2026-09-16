rule TTP_XOR_MULT_DOSStub_ea2d {
  strings:
    $key_ea2d = { be 45 [2] ca 5d [2] 8d 5f [2] ca 4e [2] 84 42 [2] 88 48 [2] 9f 43 [2] 84 0d [2] b9 }

  condition:
    any of them
}