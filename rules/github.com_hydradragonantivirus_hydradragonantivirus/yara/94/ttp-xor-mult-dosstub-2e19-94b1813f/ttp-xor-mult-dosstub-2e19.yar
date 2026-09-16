rule TTP_XOR_MULT_DOSStub_2e19 {
  strings:
    $key_2e19 = { 7a 71 [2] 0e 69 [2] 49 6b [2] 0e 7a [2] 40 76 [2] 4c 7c [2] 5b 77 [2] 40 39 [2] 7d }

  condition:
    any of them
}