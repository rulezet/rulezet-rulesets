rule TTP_XOR_MULT_DOSStub_2e2b {
  strings:
    $key_2e2b = { 7a 43 [2] 0e 5b [2] 49 59 [2] 0e 48 [2] 40 44 [2] 4c 4e [2] 5b 45 [2] 40 0b [2] 7d }

  condition:
    any of them
}