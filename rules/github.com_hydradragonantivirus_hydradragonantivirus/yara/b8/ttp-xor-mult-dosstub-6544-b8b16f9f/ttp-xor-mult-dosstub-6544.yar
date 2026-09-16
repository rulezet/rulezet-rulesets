rule TTP_XOR_MULT_DOSStub_6544 {
  strings:
    $key_6544 = { 31 2c [2] 45 34 [2] 02 36 [2] 45 27 [2] 0b 2b [2] 07 21 [2] 10 2a [2] 0b 64 [2] 36 }

  condition:
    any of them
}