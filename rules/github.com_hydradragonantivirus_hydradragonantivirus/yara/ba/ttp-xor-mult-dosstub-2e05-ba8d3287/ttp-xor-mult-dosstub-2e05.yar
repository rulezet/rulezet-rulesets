rule TTP_XOR_MULT_DOSStub_2e05 {
  strings:
    $key_2e05 = { 7a 6d [2] 0e 75 [2] 49 77 [2] 0e 66 [2] 40 6a [2] 4c 60 [2] 5b 6b [2] 40 25 [2] 7d }

  condition:
    any of them
}