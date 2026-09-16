rule TTP_XOR_MULT_DOSStub_4223 {
  strings:
    $key_4223 = { 16 4b [2] 62 53 [2] 25 51 [2] 62 40 [2] 2c 4c [2] 20 46 [2] 37 4d [2] 2c 03 [2] 11 }

  condition:
    any of them
}