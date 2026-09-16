rule TTP_XOR_MULT_DOSStub_69f0 {
  strings:
    $key_69f0 = { 3d 98 [2] 49 80 [2] 0e 82 [2] 49 93 [2] 07 9f [2] 0b 95 [2] 1c 9e [2] 07 d0 [2] 3a }

  condition:
    any of them
}