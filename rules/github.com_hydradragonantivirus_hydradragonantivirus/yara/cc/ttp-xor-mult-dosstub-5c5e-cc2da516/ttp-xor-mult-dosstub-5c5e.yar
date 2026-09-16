rule TTP_XOR_MULT_DOSStub_5c5e {
  strings:
    $key_5c5e = { 08 36 [2] 7c 2e [2] 3b 2c [2] 7c 3d [2] 32 31 [2] 3e 3b [2] 29 30 [2] 32 7e [2] 0f }

  condition:
    any of them
}