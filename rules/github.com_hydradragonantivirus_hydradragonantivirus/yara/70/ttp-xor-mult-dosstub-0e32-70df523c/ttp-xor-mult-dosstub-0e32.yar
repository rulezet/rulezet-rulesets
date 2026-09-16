rule TTP_XOR_MULT_DOSStub_0e32 {
  strings:
    $key_0e32 = { 5a 5a [2] 2e 42 [2] 69 40 [2] 2e 51 [2] 60 5d [2] 6c 57 [2] 7b 5c [2] 60 12 [2] 5d }

  condition:
    any of them
}