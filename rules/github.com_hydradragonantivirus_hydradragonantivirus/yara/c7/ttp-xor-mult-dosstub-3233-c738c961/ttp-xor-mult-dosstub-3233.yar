rule TTP_XOR_MULT_DOSStub_3233 {
  strings:
    $key_3233 = { 66 5b [2] 12 43 [2] 55 41 [2] 12 50 [2] 5c 5c [2] 50 56 [2] 47 5d [2] 5c 13 [2] 61 }

  condition:
    any of them
}