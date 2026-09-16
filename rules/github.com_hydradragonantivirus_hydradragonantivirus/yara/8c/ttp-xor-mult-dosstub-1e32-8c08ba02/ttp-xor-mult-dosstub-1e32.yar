rule TTP_XOR_MULT_DOSStub_1e32 {
  strings:
    $key_1e32 = { 4a 5a [2] 3e 42 [2] 79 40 [2] 3e 51 [2] 70 5d [2] 7c 57 [2] 6b 5c [2] 70 12 [2] 4d }

  condition:
    any of them
}