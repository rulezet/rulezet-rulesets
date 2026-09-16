rule TTP_XOR_MULT_DOSStub_7226 {
  strings:
    $key_7226 = { 26 4e [2] 52 56 [2] 15 54 [2] 52 45 [2] 1c 49 [2] 10 43 [2] 07 48 [2] 1c 06 [2] 21 }

  condition:
    any of them
}