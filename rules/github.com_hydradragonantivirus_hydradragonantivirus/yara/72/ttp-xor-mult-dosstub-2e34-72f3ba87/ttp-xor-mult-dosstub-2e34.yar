rule TTP_XOR_MULT_DOSStub_2e34 {
  strings:
    $key_2e34 = { 7a 5c [2] 0e 44 [2] 49 46 [2] 0e 57 [2] 40 5b [2] 4c 51 [2] 5b 5a [2] 40 14 [2] 7d }

  condition:
    any of them
}