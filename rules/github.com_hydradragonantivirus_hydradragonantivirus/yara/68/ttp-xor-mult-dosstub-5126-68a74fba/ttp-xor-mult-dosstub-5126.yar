rule TTP_XOR_MULT_DOSStub_5126 {
  strings:
    $key_5126 = { 05 4e [2] 71 56 [2] 36 54 [2] 71 45 [2] 3f 49 [2] 33 43 [2] 24 48 [2] 3f 06 [2] 02 }

  condition:
    any of them
}