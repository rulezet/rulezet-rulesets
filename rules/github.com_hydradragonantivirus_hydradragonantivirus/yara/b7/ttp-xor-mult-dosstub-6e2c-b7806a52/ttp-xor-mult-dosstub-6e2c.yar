rule TTP_XOR_MULT_DOSStub_6e2c {
  strings:
    $key_6e2c = { 3a 44 [2] 4e 5c [2] 09 5e [2] 4e 4f [2] 00 43 [2] 0c 49 [2] 1b 42 [2] 00 0c [2] 3d }

  condition:
    any of them
}