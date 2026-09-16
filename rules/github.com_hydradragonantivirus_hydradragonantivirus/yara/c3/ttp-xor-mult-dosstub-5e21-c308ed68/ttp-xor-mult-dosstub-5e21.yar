rule TTP_XOR_MULT_DOSStub_5e21 {
  strings:
    $key_5e21 = { 0a 49 [2] 7e 51 [2] 39 53 [2] 7e 42 [2] 30 4e [2] 3c 44 [2] 2b 4f [2] 30 01 [2] 0d }

  condition:
    any of them
}