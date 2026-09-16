rule TTP_XOR_MULT_DOSStub_1035 {
  strings:
    $key_1035 = { 44 5d [2] 30 45 [2] 77 47 [2] 30 56 [2] 7e 5a [2] 72 50 [2] 65 5b [2] 7e 15 [2] 43 }

  condition:
    any of them
}