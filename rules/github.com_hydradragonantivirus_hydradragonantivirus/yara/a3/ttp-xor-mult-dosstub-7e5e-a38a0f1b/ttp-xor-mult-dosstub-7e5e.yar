rule TTP_XOR_MULT_DOSStub_7e5e {
  strings:
    $key_7e5e = { 2a 36 [2] 5e 2e [2] 19 2c [2] 5e 3d [2] 10 31 [2] 1c 3b [2] 0b 30 [2] 10 7e [2] 2d }

  condition:
    any of them
}