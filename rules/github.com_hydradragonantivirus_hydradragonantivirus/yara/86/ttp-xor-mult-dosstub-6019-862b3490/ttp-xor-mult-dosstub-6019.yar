rule TTP_XOR_MULT_DOSStub_6019 {
  strings:
    $key_6019 = { 34 71 [2] 40 69 [2] 07 6b [2] 40 7a [2] 0e 76 [2] 02 7c [2] 15 77 [2] 0e 39 [2] 33 }

  condition:
    any of them
}