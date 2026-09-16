rule TTP_XOR_MULT_DOSStub_7a24 {
  strings:
    $key_7a24 = { 2e 4c [2] 5a 54 [2] 1d 56 [2] 5a 47 [2] 14 4b [2] 18 41 [2] 0f 4a [2] 14 04 [2] 29 }

  condition:
    any of them
}