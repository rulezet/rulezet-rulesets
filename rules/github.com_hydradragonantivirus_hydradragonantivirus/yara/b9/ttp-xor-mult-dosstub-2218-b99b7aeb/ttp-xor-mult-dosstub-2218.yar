rule TTP_XOR_MULT_DOSStub_2218 {
  strings:
    $key_2218 = { 76 70 [2] 02 68 [2] 45 6a [2] 02 7b [2] 4c 77 [2] 40 7d [2] 57 76 [2] 4c 38 [2] 71 }

  condition:
    any of them
}