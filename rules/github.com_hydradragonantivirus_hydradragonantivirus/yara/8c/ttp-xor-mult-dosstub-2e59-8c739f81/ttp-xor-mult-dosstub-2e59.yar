rule TTP_XOR_MULT_DOSStub_2e59 {
  strings:
    $key_2e59 = { 7a 31 [2] 0e 29 [2] 49 2b [2] 0e 3a [2] 40 36 [2] 4c 3c [2] 5b 37 [2] 40 79 [2] 7d }

  condition:
    any of them
}