rule TTP_XOR_MULT_DOSStub_2538 {
  strings:
    $key_2538 = { 71 50 [2] 05 48 [2] 42 4a [2] 05 5b [2] 4b 57 [2] 47 5d [2] 50 56 [2] 4b 18 [2] 76 }

  condition:
    any of them
}