rule TTP_XOR_MULT_DOSStub_6960 {
  strings:
    $key_6960 = { 3d 08 [2] 49 10 [2] 0e 12 [2] 49 03 [2] 07 0f [2] 0b 05 [2] 1c 0e [2] 07 40 [2] 3a }

  condition:
    any of them
}