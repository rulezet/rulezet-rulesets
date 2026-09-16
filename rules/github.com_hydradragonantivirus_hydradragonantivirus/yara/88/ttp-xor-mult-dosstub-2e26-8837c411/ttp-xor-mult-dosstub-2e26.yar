rule TTP_XOR_MULT_DOSStub_2e26 {
  strings:
    $key_2e26 = { 7a 4e [2] 0e 56 [2] 49 54 [2] 0e 45 [2] 40 49 [2] 4c 43 [2] 5b 48 [2] 40 06 [2] 7d }

  condition:
    any of them
}