rule TTP_XOR_MULT_DOSStub_2e32 {
  strings:
    $key_2e32 = { 7a 5a [2] 0e 42 [2] 49 40 [2] 0e 51 [2] 40 5d [2] 4c 57 [2] 5b 5c [2] 40 12 [2] 7d }

  condition:
    any of them
}