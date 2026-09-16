rule TTP_XOR_MULT_DOSStub_7e58 {
  strings:
    $key_7e58 = { 2a 30 [2] 5e 28 [2] 19 2a [2] 5e 3b [2] 10 37 [2] 1c 3d [2] 0b 36 [2] 10 78 [2] 2d }

  condition:
    any of them
}