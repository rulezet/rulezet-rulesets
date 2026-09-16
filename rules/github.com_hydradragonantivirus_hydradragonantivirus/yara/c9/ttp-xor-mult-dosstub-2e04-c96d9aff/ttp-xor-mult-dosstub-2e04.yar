rule TTP_XOR_MULT_DOSStub_2e04 {
  strings:
    $key_2e04 = { 7a 6c [2] 0e 74 [2] 49 76 [2] 0e 67 [2] 40 6b [2] 4c 61 [2] 5b 6a [2] 40 24 [2] 7d }

  condition:
    any of them
}