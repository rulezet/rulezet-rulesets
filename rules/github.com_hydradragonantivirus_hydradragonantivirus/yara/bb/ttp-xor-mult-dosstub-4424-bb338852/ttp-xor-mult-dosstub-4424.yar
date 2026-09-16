rule TTP_XOR_MULT_DOSStub_4424 {
  strings:
    $key_4424 = { 10 4c [2] 64 54 [2] 23 56 [2] 64 47 [2] 2a 4b [2] 26 41 [2] 31 4a [2] 2a 04 [2] 17 }

  condition:
    any of them
}