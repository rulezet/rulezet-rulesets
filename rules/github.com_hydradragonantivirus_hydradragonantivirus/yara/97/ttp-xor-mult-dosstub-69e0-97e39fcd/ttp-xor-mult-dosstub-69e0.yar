rule TTP_XOR_MULT_DOSStub_69e0 {
  strings:
    $key_69e0 = { 3d 88 [2] 49 90 [2] 0e 92 [2] 49 83 [2] 07 8f [2] 0b 85 [2] 1c 8e [2] 07 c0 [2] 3a }

  condition:
    any of them
}