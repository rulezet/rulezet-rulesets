rule TTP_XOR_MULT_DOSStub_6e11 {
  strings:
    $key_6e11 = { 3a 79 [2] 4e 61 [2] 09 63 [2] 4e 72 [2] 00 7e [2] 0c 74 [2] 1b 7f [2] 00 31 [2] 3d }

  condition:
    any of them
}