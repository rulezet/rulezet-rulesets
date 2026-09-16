rule TTP_XOR_MULT_DOSStub_1626 {
  strings:
    $key_1626 = { 42 4e [2] 36 56 [2] 71 54 [2] 36 45 [2] 78 49 [2] 74 43 [2] 63 48 [2] 78 06 [2] 45 }

  condition:
    any of them
}