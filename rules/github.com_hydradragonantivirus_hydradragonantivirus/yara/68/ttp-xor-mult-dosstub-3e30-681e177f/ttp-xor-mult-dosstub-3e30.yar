rule TTP_XOR_MULT_DOSStub_3e30 {
  strings:
    $key_3e30 = { 6a 58 [2] 1e 40 [2] 59 42 [2] 1e 53 [2] 50 5f [2] 5c 55 [2] 4b 5e [2] 50 10 [2] 6d }

  condition:
    any of them
}