rule TTP_XOR_MULT_DOSStub_7b43 {
  strings:
    $key_7b43 = { 2f 2b [2] 5b 33 [2] 1c 31 [2] 5b 20 [2] 15 2c [2] 19 26 [2] 0e 2d [2] 15 63 [2] 28 }

  condition:
    any of them
}