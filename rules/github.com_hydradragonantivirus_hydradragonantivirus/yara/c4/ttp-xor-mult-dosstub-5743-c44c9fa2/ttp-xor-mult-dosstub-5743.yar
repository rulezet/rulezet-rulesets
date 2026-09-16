rule TTP_XOR_MULT_DOSStub_5743 {
  strings:
    $key_5743 = { 03 2b [2] 77 33 [2] 30 31 [2] 77 20 [2] 39 2c [2] 35 26 [2] 22 2d [2] 39 63 [2] 04 }

  condition:
    any of them
}