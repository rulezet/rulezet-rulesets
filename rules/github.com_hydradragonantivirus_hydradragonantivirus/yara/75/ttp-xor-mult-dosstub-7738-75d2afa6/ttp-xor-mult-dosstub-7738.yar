rule TTP_XOR_MULT_DOSStub_7738 {
  strings:
    $key_7738 = { 23 50 [2] 57 48 [2] 10 4a [2] 57 5b [2] 19 57 [2] 15 5d [2] 02 56 [2] 19 18 [2] 24 }

  condition:
    any of them
}