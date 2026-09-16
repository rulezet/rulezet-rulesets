rule TTP_XOR_MULT_DOSStub_6e0c {
  strings:
    $key_6e0c = { 3a 64 [2] 4e 7c [2] 09 7e [2] 4e 6f [2] 00 63 [2] 0c 69 [2] 1b 62 [2] 00 2c [2] 3d }

  condition:
    any of them
}