rule TTP_XOR_MULT_DOSStub_3749 {
  strings:
    $key_3749 = { 63 21 [2] 17 39 [2] 50 3b [2] 17 2a [2] 59 26 [2] 55 2c [2] 42 27 [2] 59 69 [2] 64 }

  condition:
    any of them
}