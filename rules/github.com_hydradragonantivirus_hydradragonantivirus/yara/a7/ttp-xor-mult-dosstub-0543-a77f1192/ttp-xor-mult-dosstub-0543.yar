rule TTP_XOR_MULT_DOSStub_0543 {
  strings:
    $key_0543 = { 51 2b [2] 25 33 [2] 62 31 [2] 25 20 [2] 6b 2c [2] 67 26 [2] 70 2d [2] 6b 63 [2] 56 }

  condition:
    any of them
}