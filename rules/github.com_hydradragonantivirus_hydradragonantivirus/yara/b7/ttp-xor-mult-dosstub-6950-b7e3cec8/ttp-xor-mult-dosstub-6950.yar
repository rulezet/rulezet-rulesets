rule TTP_XOR_MULT_DOSStub_6950 {
  strings:
    $key_6950 = { 3d 38 [2] 49 20 [2] 0e 22 [2] 49 33 [2] 07 3f [2] 0b 35 [2] 1c 3e [2] 07 70 [2] 3a }

  condition:
    any of them
}