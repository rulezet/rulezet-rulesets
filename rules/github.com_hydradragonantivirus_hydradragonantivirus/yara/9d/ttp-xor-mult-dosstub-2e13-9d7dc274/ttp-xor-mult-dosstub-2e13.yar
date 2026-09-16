rule TTP_XOR_MULT_DOSStub_2e13 {
  strings:
    $key_2e13 = { 7a 7b [2] 0e 63 [2] 49 61 [2] 0e 70 [2] 40 7c [2] 4c 76 [2] 5b 7d [2] 40 33 [2] 7d }

  condition:
    any of them
}