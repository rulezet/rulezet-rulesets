rule TTP_XOR_MULT_DOSStub_2e37 {
  strings:
    $key_2e37 = { 7a 5f [2] 0e 47 [2] 49 45 [2] 0e 54 [2] 40 58 [2] 4c 52 [2] 5b 59 [2] 40 17 [2] 7d }

  condition:
    any of them
}