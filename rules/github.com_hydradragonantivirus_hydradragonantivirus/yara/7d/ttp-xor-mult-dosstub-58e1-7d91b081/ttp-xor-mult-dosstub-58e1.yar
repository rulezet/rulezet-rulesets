rule TTP_XOR_MULT_DOSStub_58e1 {
  strings:
    $key_58e1 = { 0c 89 [2] 78 91 [2] 3f 93 [2] 78 82 [2] 36 8e [2] 3a 84 [2] 2d 8f [2] 36 c1 [2] 0b }

  condition:
    any of them
}