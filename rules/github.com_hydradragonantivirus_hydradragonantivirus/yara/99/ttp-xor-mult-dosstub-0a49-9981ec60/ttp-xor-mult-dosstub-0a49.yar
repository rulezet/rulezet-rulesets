rule TTP_XOR_MULT_DOSStub_0a49 {
  strings:
    $key_0a49 = { 5e 21 [2] 2a 39 [2] 6d 3b [2] 2a 2a [2] 64 26 [2] 68 2c [2] 7f 27 [2] 64 69 [2] 59 }

  condition:
    any of them
}