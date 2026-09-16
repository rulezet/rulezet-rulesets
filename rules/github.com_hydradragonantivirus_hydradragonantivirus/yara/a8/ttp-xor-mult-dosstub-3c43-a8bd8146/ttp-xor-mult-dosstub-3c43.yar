rule TTP_XOR_MULT_DOSStub_3c43 {
  strings:
    $key_3c43 = { 68 2b [2] 1c 33 [2] 5b 31 [2] 1c 20 [2] 52 2c [2] 5e 26 [2] 49 2d [2] 52 63 [2] 6f }

  condition:
    any of them
}