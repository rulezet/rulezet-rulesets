rule TTP_XOR_MULT_DOSStub_705d {
  strings:
    $key_705d = { 24 35 [2] 50 2d [2] 17 2f [2] 50 3e [2] 1e 32 [2] 12 38 [2] 05 33 [2] 1e 7d [2] 23 }

  condition:
    any of them
}