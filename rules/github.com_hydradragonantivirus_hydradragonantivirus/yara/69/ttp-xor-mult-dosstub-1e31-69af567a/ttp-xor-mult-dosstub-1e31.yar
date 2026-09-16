rule TTP_XOR_MULT_DOSStub_1e31 {
  strings:
    $key_1e31 = { 4a 59 [2] 3e 41 [2] 79 43 [2] 3e 52 [2] 70 5e [2] 7c 54 [2] 6b 5f [2] 70 11 [2] 4d }

  condition:
    any of them
}