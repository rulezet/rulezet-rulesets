rule TTP_XOR_MULT_DOSStub_3ee2 {
  strings:
    $key_3ee2 = { 6a 8a [2] 1e 92 [2] 59 90 [2] 1e 81 [2] 50 8d [2] 5c 87 [2] 4b 8c [2] 50 c2 [2] 6d }

  condition:
    any of them
}