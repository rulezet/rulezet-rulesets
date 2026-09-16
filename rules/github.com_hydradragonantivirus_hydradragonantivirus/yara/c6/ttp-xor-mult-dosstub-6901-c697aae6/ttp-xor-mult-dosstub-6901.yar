rule TTP_XOR_MULT_DOSStub_6901 {
  strings:
    $key_6901 = { 3d 69 [2] 49 71 [2] 0e 73 [2] 49 62 [2] 07 6e [2] 0b 64 [2] 1c 6f [2] 07 21 [2] 3a }

  condition:
    any of them
}