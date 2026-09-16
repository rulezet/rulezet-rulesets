rule TTP_XOR_MULT_DOSStub_3c5e {
  strings:
    $key_3c5e = { 68 36 [2] 1c 2e [2] 5b 2c [2] 1c 3d [2] 52 31 [2] 5e 3b [2] 49 30 [2] 52 7e [2] 6f }

  condition:
    any of them
}