rule TTP_XOR_MULT_DOSStub_3e31 {
  strings:
    $key_3e31 = { 6a 59 [2] 1e 41 [2] 59 43 [2] 1e 52 [2] 50 5e [2] 5c 54 [2] 4b 5f [2] 50 11 [2] 6d }

  condition:
    any of them
}