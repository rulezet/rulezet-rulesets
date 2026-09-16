rule TTP_XOR_MULT_DOSStub_2e08 {
  strings:
    $key_2e08 = { 7a 60 [2] 0e 78 [2] 49 7a [2] 0e 6b [2] 40 67 [2] 4c 6d [2] 5b 66 [2] 40 28 [2] 7d }

  condition:
    any of them
}