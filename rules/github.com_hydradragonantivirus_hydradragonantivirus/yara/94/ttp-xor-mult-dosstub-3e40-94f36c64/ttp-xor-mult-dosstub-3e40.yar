rule TTP_XOR_MULT_DOSStub_3e40 {
  strings:
    $key_3e40 = { 6a 28 [2] 1e 30 [2] 59 32 [2] 1e 23 [2] 50 2f [2] 5c 25 [2] 4b 2e [2] 50 60 [2] 6d }

  condition:
    any of them
}