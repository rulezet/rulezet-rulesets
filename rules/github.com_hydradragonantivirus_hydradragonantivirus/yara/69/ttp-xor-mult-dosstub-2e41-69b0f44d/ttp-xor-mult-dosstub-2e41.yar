rule TTP_XOR_MULT_DOSStub_2e41 {
  strings:
    $key_2e41 = { 7a 29 [2] 0e 31 [2] 49 33 [2] 0e 22 [2] 40 2e [2] 4c 24 [2] 5b 2f [2] 40 61 [2] 7d }

  condition:
    any of them
}