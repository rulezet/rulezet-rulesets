rule TTP_XOR_MULT_DOSStub_6921 {
  strings:
    $key_6921 = { 3d 49 [2] 49 51 [2] 0e 53 [2] 49 42 [2] 07 4e [2] 0b 44 [2] 1c 4f [2] 07 01 [2] 3a }

  condition:
    any of them
}