rule TTP_XOR_MULT_DOSStub_6e4c {
  strings:
    $key_6e4c = { 3a 24 [2] 4e 3c [2] 09 3e [2] 4e 2f [2] 00 23 [2] 0c 29 [2] 1b 22 [2] 00 6c [2] 3d }

  condition:
    any of them
}