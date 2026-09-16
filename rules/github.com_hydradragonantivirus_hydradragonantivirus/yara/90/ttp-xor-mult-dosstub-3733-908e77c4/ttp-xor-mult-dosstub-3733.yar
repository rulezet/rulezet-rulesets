rule TTP_XOR_MULT_DOSStub_3733 {
  strings:
    $key_3733 = { 63 5b [2] 17 43 [2] 50 41 [2] 17 50 [2] 59 5c [2] 55 56 [2] 42 5d [2] 59 13 [2] 64 }

  condition:
    any of them
}