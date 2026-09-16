rule TTP_XOR_MULT_DOSStub_69f6 {
  strings:
    $key_69f6 = { 3d 9e [2] 49 86 [2] 0e 84 [2] 49 95 [2] 07 99 [2] 0b 93 [2] 1c 98 [2] 07 d6 [2] 3a }

  condition:
    any of them
}