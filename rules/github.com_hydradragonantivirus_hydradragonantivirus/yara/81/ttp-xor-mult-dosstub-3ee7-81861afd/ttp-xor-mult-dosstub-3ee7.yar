rule TTP_XOR_MULT_DOSStub_3ee7 {
  strings:
    $key_3ee7 = { 6a 8f [2] 1e 97 [2] 59 95 [2] 1e 84 [2] 50 88 [2] 5c 82 [2] 4b 89 [2] 50 c7 [2] 6d }

  condition:
    any of them
}