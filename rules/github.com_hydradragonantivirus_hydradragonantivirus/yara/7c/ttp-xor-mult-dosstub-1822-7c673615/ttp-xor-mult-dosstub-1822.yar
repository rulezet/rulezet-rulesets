rule TTP_XOR_MULT_DOSStub_1822 {
  strings:
    $key_1822 = { 4c 4a [2] 38 52 [2] 7f 50 [2] 38 41 [2] 76 4d [2] 7a 47 [2] 6d 4c [2] 76 02 [2] 4b }

  condition:
    any of them
}