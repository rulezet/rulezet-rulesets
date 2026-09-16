rule TTP_XOR_MULT_DOSStub_2226 {
  strings:
    $key_2226 = { 76 4e [2] 02 56 [2] 45 54 [2] 02 45 [2] 4c 49 [2] 40 43 [2] 57 48 [2] 4c 06 [2] 71 }

  condition:
    any of them
}