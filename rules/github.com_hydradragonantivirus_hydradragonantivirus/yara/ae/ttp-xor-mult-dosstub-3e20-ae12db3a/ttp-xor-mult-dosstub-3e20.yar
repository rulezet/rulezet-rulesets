rule TTP_XOR_MULT_DOSStub_3e20 {
  strings:
    $key_3e20 = { 6a 48 [2] 1e 50 [2] 59 52 [2] 1e 43 [2] 50 4f [2] 5c 45 [2] 4b 4e [2] 50 00 [2] 6d }

  condition:
    any of them
}