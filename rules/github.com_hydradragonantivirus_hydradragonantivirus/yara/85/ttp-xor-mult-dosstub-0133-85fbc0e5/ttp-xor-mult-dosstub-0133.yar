rule TTP_XOR_MULT_DOSStub_0133 {
  strings:
    $key_0133 = { 55 5b [2] 21 43 [2] 66 41 [2] 21 50 [2] 6f 5c [2] 63 56 [2] 74 5d [2] 6f 13 [2] 52 }

  condition:
    any of them
}