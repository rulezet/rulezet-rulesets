rule TTP_XOR_MULT_DOSStub_6967 {
  strings:
    $key_6967 = { 3d 0f [2] 49 17 [2] 0e 15 [2] 49 04 [2] 07 08 [2] 0b 02 [2] 1c 09 [2] 07 47 [2] 3a }

  condition:
    any of them
}