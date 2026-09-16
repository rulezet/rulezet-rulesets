rule TTP_XOR_MULT_DOSStub_2543 {
  strings:
    $key_2543 = { 71 2b [2] 05 33 [2] 42 31 [2] 05 20 [2] 4b 2c [2] 47 26 [2] 50 2d [2] 4b 63 [2] 76 }

  condition:
    any of them
}