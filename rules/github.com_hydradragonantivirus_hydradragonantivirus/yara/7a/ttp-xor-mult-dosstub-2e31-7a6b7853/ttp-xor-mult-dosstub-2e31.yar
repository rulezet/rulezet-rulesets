rule TTP_XOR_MULT_DOSStub_2e31 {
  strings:
    $key_2e31 = { 7a 59 [2] 0e 41 [2] 49 43 [2] 0e 52 [2] 40 5e [2] 4c 54 [2] 5b 5f [2] 40 11 [2] 7d }

  condition:
    any of them
}