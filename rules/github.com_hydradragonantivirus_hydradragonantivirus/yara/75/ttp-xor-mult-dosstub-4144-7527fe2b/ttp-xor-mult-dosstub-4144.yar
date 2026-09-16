rule TTP_XOR_MULT_DOSStub_4144 {
  strings:
    $key_4144 = { 15 2c [2] 61 34 [2] 26 36 [2] 61 27 [2] 2f 2b [2] 23 21 [2] 34 2a [2] 2f 64 [2] 12 }

  condition:
    any of them
}