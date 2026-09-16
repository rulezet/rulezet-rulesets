rule TTP_XOR_MULT_DOSStub_7144 {
  strings:
    $key_7144 = { 25 2c [2] 51 34 [2] 16 36 [2] 51 27 [2] 1f 2b [2] 13 21 [2] 04 2a [2] 1f 64 [2] 22 }

  condition:
    any of them
}