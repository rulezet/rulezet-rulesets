rule TTP_XOR_MULT_DOSStub_0b43 {
  strings:
    $key_0b43 = { 5f 2b [2] 2b 33 [2] 6c 31 [2] 2b 20 [2] 65 2c [2] 69 26 [2] 7e 2d [2] 65 63 [2] 58 }

  condition:
    any of them
}