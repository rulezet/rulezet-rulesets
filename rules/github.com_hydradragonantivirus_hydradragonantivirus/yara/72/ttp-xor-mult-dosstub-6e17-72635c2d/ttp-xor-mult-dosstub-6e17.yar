rule TTP_XOR_MULT_DOSStub_6e17 {
  strings:
    $key_6e17 = { 3a 7f [2] 4e 67 [2] 09 65 [2] 4e 74 [2] 00 78 [2] 0c 72 [2] 1b 79 [2] 00 37 [2] 3d }

  condition:
    any of them
}