rule TTP_XOR_MULT_DOSStub_7133 {
  strings:
    $key_7133 = { 25 5b [2] 51 43 [2] 16 41 [2] 51 50 [2] 1f 5c [2] 13 56 [2] 04 5d [2] 1f 13 [2] 22 }

  condition:
    any of them
}