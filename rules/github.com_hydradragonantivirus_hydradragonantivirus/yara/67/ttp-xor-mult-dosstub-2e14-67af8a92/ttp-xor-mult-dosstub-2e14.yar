rule TTP_XOR_MULT_DOSStub_2e14 {
  strings:
    $key_2e14 = { 7a 7c [2] 0e 64 [2] 49 66 [2] 0e 77 [2] 40 7b [2] 4c 71 [2] 5b 7a [2] 40 34 [2] 7d }

  condition:
    any of them
}