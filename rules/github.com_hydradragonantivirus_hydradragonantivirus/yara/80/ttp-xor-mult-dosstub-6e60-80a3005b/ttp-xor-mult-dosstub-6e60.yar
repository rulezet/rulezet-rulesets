rule TTP_XOR_MULT_DOSStub_6e60 {
  strings:
    $key_6e60 = { 3a 08 [2] 4e 10 [2] 09 12 [2] 4e 03 [2] 00 0f [2] 0c 05 [2] 1b 0e [2] 00 40 [2] 3d }

  condition:
    any of them
}