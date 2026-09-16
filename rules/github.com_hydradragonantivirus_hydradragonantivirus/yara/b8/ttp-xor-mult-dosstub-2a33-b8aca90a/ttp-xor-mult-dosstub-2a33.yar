rule TTP_XOR_MULT_DOSStub_2a33 {
  strings:
    $key_2a33 = { 7e 5b [2] 0a 43 [2] 4d 41 [2] 0a 50 [2] 44 5c [2] 48 56 [2] 5f 5d [2] 44 13 [2] 79 }

  condition:
    any of them
}