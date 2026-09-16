rule TTP_XOR_MULT_DOSStub_3033 {
  strings:
    $key_3033 = { 64 5b [2] 10 43 [2] 57 41 [2] 10 50 [2] 5e 5c [2] 52 56 [2] 45 5d [2] 5e 13 [2] 63 }

  condition:
    any of them
}