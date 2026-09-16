rule TTP_XOR_MULT_DOSStub_5b33 {
  strings:
    $key_5b33 = { 0f 5b [2] 7b 43 [2] 3c 41 [2] 7b 50 [2] 35 5c [2] 39 56 [2] 2e 5d [2] 35 13 [2] 08 }

  condition:
    any of them
}