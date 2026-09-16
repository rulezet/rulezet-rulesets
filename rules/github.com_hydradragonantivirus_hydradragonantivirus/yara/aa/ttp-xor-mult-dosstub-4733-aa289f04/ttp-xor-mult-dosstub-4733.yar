rule TTP_XOR_MULT_DOSStub_4733 {
  strings:
    $key_4733 = { 13 5b [2] 67 43 [2] 20 41 [2] 67 50 [2] 29 5c [2] 25 56 [2] 32 5d [2] 29 13 [2] 14 }

  condition:
    any of them
}