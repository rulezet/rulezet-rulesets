rule TTP_XOR_MULT_DOSStub_1e34 {
  strings:
    $key_1e34 = { 4a 5c [2] 3e 44 [2] 79 46 [2] 3e 57 [2] 70 5b [2] 7c 51 [2] 6b 5a [2] 70 14 [2] 4d }

  condition:
    any of them
}