rule TTP_XOR_MULT_DOSStub_4429 {
  strings:
    $key_4429 = { 10 41 [2] 64 59 [2] 23 5b [2] 64 4a [2] 2a 46 [2] 26 4c [2] 31 47 [2] 2a 09 [2] 17 }

  condition:
    any of them
}