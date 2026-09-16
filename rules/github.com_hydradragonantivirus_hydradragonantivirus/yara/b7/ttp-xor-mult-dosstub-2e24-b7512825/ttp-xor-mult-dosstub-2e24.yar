rule TTP_XOR_MULT_DOSStub_2e24 {
  strings:
    $key_2e24 = { 7a 4c [2] 0e 54 [2] 49 56 [2] 0e 47 [2] 40 4b [2] 4c 41 [2] 5b 4a [2] 40 04 [2] 7d }

  condition:
    any of them
}