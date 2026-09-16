rule TTP_XOR_MULT_DOSStub_7e41 {
  strings:
    $key_7e41 = { 2a 29 [2] 5e 31 [2] 19 33 [2] 5e 22 [2] 10 2e [2] 1c 24 [2] 0b 2f [2] 10 61 [2] 2d }

  condition:
    any of them
}