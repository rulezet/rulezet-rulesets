rule TTP_XOR_MULT_DOSStub_2e51 {
  strings:
    $key_2e51 = { 7a 39 [2] 0e 21 [2] 49 23 [2] 0e 32 [2] 40 3e [2] 4c 34 [2] 5b 3f [2] 40 71 [2] 7d }

  condition:
    any of them
}