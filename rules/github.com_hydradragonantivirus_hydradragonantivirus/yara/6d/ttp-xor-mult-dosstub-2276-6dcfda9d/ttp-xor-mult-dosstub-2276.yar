rule TTP_XOR_MULT_DOSStub_2276 {
  strings:
    $key_2276 = { 76 1e [2] 02 06 [2] 45 04 [2] 02 15 [2] 4c 19 [2] 40 13 [2] 57 18 [2] 4c 56 [2] 71 }

  condition:
    any of them
}