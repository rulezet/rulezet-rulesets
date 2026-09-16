rule TTP_XOR_MULT_DOSStub_0e31 {
  strings:
    $key_0e31 = { 5a 59 [2] 2e 41 [2] 69 43 [2] 2e 52 [2] 60 5e [2] 6c 54 [2] 7b 5f [2] 60 11 [2] 5d }

  condition:
    any of them
}