rule TTP_XOR_MULT_DOSStub_1273 {
  strings:
    $key_1273 = { 46 1b [2] 32 03 [2] 75 01 [2] 32 10 [2] 7c 1c [2] 70 16 [2] 67 1d [2] 7c 53 [2] 41 }

  condition:
    any of them
}