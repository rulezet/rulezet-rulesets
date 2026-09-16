rule TTP_XOR_MULT_DOSStub_4538 {
  strings:
    $key_4538 = { 11 50 [2] 65 48 [2] 22 4a [2] 65 5b [2] 2b 57 [2] 27 5d [2] 30 56 [2] 2b 18 [2] 16 }

  condition:
    any of them
}