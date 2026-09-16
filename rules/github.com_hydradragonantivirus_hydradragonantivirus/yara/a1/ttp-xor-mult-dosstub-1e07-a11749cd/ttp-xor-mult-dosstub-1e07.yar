rule TTP_XOR_MULT_DOSStub_1e07 {
  strings:
    $key_1e07 = { 4a 6f [2] 3e 77 [2] 79 75 [2] 3e 64 [2] 70 68 [2] 7c 62 [2] 6b 69 [2] 70 27 [2] 4d }

  condition:
    any of them
}