rule TTP_XOR_MULT_DOSStub_2e28 {
  strings:
    $key_2e28 = { 7a 40 [2] 0e 58 [2] 49 5a [2] 0e 4b [2] 40 47 [2] 4c 4d [2] 5b 46 [2] 40 08 [2] 7d }

  condition:
    any of them
}