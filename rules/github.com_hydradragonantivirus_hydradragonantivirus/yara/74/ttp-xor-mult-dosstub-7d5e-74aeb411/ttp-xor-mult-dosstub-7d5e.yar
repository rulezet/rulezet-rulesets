rule TTP_XOR_MULT_DOSStub_7d5e {
  strings:
    $key_7d5e = { 29 36 [2] 5d 2e [2] 1a 2c [2] 5d 3d [2] 13 31 [2] 1f 3b [2] 08 30 [2] 13 7e [2] 2e }

  condition:
    any of them
}