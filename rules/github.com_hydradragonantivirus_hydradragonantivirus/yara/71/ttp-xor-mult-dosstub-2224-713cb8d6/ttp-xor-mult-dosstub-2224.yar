rule TTP_XOR_MULT_DOSStub_2224 {
  strings:
    $key_2224 = { 76 4c [2] 02 54 [2] 45 56 [2] 02 47 [2] 4c 4b [2] 40 41 [2] 57 4a [2] 4c 04 [2] 71 }

  condition:
    any of them
}