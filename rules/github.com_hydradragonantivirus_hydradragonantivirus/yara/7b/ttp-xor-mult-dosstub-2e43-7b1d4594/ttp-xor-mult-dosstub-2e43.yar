rule TTP_XOR_MULT_DOSStub_2e43 {
  strings:
    $key_2e43 = { 7a 2b [2] 0e 33 [2] 49 31 [2] 0e 20 [2] 40 2c [2] 4c 26 [2] 5b 2d [2] 40 63 [2] 7d }

  condition:
    any of them
}