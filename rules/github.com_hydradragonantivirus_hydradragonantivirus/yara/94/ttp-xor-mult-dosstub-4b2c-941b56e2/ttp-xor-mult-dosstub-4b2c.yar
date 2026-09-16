rule TTP_XOR_MULT_DOSStub_4b2c {
  strings:
    $key_4b2c = { 1f 44 [2] 6b 5c [2] 2c 5e [2] 6b 4f [2] 25 43 [2] 29 49 [2] 3e 42 [2] 25 0c [2] 18 }

  condition:
    any of them
}