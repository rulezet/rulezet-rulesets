rule TTP_XOR_MULT_DOSStub_6e41 {
  strings:
    $key_6e41 = { 3a 29 [2] 4e 31 [2] 09 33 [2] 4e 22 [2] 00 2e [2] 0c 24 [2] 1b 2f [2] 00 61 [2] 3d }

  condition:
    any of them
}