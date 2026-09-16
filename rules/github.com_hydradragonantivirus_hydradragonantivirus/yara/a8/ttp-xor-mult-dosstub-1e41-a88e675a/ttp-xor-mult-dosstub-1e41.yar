rule TTP_XOR_MULT_DOSStub_1e41 {
  strings:
    $key_1e41 = { 4a 29 [2] 3e 31 [2] 79 33 [2] 3e 22 [2] 70 2e [2] 7c 24 [2] 6b 2f [2] 70 61 [2] 4d }

  condition:
    any of them
}