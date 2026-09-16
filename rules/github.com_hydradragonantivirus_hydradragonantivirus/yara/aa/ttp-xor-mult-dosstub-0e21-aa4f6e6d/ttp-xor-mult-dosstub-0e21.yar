rule TTP_XOR_MULT_DOSStub_0e21 {
  strings:
    $key_0e21 = { 5a 49 [2] 2e 51 [2] 69 53 [2] 2e 42 [2] 60 4e [2] 6c 44 [2] 7b 4f [2] 60 01 [2] 5d }

  condition:
    any of them
}