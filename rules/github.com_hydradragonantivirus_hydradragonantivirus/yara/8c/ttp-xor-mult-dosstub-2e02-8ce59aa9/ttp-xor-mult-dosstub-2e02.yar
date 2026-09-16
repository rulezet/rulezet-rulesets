rule TTP_XOR_MULT_DOSStub_2e02 {
  strings:
    $key_2e02 = { 7a 6a [2] 0e 72 [2] 49 70 [2] 0e 61 [2] 40 6d [2] 4c 67 [2] 5b 6c [2] 40 22 [2] 7d }

  condition:
    any of them
}