rule TTP_XOR_MULT_DOSStub_2b44 {
  strings:
    $key_2b44 = { 7f 2c [2] 0b 34 [2] 4c 36 [2] 0b 27 [2] 45 2b [2] 49 21 [2] 5e 2a [2] 45 64 [2] 78 }

  condition:
    any of them
}