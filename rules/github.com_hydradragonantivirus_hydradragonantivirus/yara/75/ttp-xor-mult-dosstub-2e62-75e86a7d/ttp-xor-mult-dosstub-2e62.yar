rule TTP_XOR_MULT_DOSStub_2e62 {
  strings:
    $key_2e62 = { 7a 0a [2] 0e 12 [2] 49 10 [2] 0e 01 [2] 40 0d [2] 4c 07 [2] 5b 0c [2] 40 42 [2] 7d }

  condition:
    any of them
}