rule TTP_XOR_MULT_DOSStub_4c33 {
  strings:
    $key_4c33 = { 18 5b [2] 6c 43 [2] 2b 41 [2] 6c 50 [2] 22 5c [2] 2e 56 [2] 39 5d [2] 22 13 [2] 1f }

  condition:
    any of them
}