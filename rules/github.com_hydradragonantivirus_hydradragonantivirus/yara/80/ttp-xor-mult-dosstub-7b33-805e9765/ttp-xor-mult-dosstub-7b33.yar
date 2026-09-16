rule TTP_XOR_MULT_DOSStub_7b33 {
  strings:
    $key_7b33 = { 2f 5b [2] 5b 43 [2] 1c 41 [2] 5b 50 [2] 15 5c [2] 19 56 [2] 0e 5d [2] 15 13 [2] 28 }

  condition:
    any of them
}