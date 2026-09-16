rule TTP_XOR_MULT_DOSStub_0e41 {
  strings:
    $key_0e41 = { 5a 29 [2] 2e 31 [2] 69 33 [2] 2e 22 [2] 60 2e [2] 6c 24 [2] 7b 2f [2] 60 61 [2] 5d }

  condition:
    any of them
}