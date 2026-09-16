rule TTP_XOR_MULT_DOSStub_795e {
  strings:
    $key_795e = { 2d 36 [2] 59 2e [2] 1e 2c [2] 59 3d [2] 17 31 [2] 1b 3b [2] 0c 30 [2] 17 7e [2] 2a }

  condition:
    any of them
}