rule TTP_XOR_MULT_DOSStub_3c5b {
  strings:
    $key_3c5b = { 68 33 [2] 1c 2b [2] 5b 29 [2] 1c 38 [2] 52 34 [2] 5e 3e [2] 49 35 [2] 52 7b [2] 6f }

  condition:
    any of them
}