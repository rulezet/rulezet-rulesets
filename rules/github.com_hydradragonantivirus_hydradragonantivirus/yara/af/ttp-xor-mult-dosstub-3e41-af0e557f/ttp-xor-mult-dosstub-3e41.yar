rule TTP_XOR_MULT_DOSStub_3e41 {
  strings:
    $key_3e41 = { 6a 29 [2] 1e 31 [2] 59 33 [2] 1e 22 [2] 50 2e [2] 5c 24 [2] 4b 2f [2] 50 61 [2] 6d }

  condition:
    any of them
}