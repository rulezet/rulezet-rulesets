rule TTP_XOR_MULT_DOSStub_7c10 {
  strings:
    $key_7c10 = { 28 78 [2] 5c 60 [2] 1b 62 [2] 5c 73 [2] 12 7f [2] 1e 75 [2] 09 7e [2] 12 30 [2] 2f }

  condition:
    any of them
}