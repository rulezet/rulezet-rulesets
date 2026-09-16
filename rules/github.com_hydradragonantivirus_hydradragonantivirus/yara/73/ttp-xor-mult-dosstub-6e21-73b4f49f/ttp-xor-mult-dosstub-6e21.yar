rule TTP_XOR_MULT_DOSStub_6e21 {
  strings:
    $key_6e21 = { 3a 49 [2] 4e 51 [2] 09 53 [2] 4e 42 [2] 00 4e [2] 0c 44 [2] 1b 4f [2] 00 01 [2] 3d }

  condition:
    any of them
}