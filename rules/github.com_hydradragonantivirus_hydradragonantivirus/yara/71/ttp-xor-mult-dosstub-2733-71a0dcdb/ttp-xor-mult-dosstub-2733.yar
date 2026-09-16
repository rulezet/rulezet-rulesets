rule TTP_XOR_MULT_DOSStub_2733 {
  strings:
    $key_2733 = { 73 5b [2] 07 43 [2] 40 41 [2] 07 50 [2] 49 5c [2] 45 56 [2] 52 5d [2] 49 13 [2] 74 }

  condition:
    any of them
}