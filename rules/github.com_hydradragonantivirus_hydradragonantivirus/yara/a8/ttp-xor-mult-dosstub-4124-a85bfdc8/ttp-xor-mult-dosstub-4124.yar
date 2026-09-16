rule TTP_XOR_MULT_DOSStub_4124 {
  strings:
    $key_4124 = { 15 4c [2] 61 54 [2] 26 56 [2] 61 47 [2] 2f 4b [2] 23 41 [2] 34 4a [2] 2f 04 [2] 12 }

  condition:
    any of them
}