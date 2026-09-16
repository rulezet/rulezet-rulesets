rule TTP_XOR_MULT_DOSStub_2e63 {
  strings:
    $key_2e63 = { 7a 0b [2] 0e 13 [2] 49 11 [2] 0e 00 [2] 40 0c [2] 4c 06 [2] 5b 0d [2] 40 43 [2] 7d }

  condition:
    any of them
}