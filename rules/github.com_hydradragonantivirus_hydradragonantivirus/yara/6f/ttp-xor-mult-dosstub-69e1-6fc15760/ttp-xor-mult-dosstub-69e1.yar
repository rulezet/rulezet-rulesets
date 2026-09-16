rule TTP_XOR_MULT_DOSStub_69e1 {
  strings:
    $key_69e1 = { 3d 89 [2] 49 91 [2] 0e 93 [2] 49 82 [2] 07 8e [2] 0b 84 [2] 1c 8f [2] 07 c1 [2] 3a }

  condition:
    any of them
}