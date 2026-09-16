rule TTP_XOR_MULT_DOSStub_5e57 {
  strings:
    $key_5e57 = { 0a 3f [2] 7e 27 [2] 39 25 [2] 7e 34 [2] 30 38 [2] 3c 32 [2] 2b 39 [2] 30 77 [2] 0d }

  condition:
    any of them
}