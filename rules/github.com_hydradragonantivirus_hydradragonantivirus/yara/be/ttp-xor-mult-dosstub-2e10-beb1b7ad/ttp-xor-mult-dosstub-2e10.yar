rule TTP_XOR_MULT_DOSStub_2e10 {
  strings:
    $key_2e10 = { 7a 78 [2] 0e 60 [2] 49 62 [2] 0e 73 [2] 40 7f [2] 4c 75 [2] 5b 7e [2] 40 30 [2] 7d }

  condition:
    any of them
}