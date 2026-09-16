rule TTP_XOR_MULT_DOSStub_2946 {
  strings:
    $key_2946 = { 7d 2e [2] 09 36 [2] 4e 34 [2] 09 25 [2] 47 29 [2] 4b 23 [2] 5c 28 [2] 47 66 [2] 7a }

  condition:
    any of them
}