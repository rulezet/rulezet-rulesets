rule TTP_XOR_MULT_DOSStub_5624 {
  strings:
    $key_5624 = { 02 4c [2] 76 54 [2] 31 56 [2] 76 47 [2] 38 4b [2] 34 41 [2] 23 4a [2] 38 04 [2] 05 }

  condition:
    any of them
}