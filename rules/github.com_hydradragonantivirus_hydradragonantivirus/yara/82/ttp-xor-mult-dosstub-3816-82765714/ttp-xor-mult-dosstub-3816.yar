rule TTP_XOR_MULT_DOSStub_3816 {
  strings:
    $key_3816 = { 6c 7e [2] 18 66 [2] 5f 64 [2] 18 75 [2] 56 79 [2] 5a 73 [2] 4d 78 [2] 56 36 [2] 6b }

  condition:
    any of them
}