rule TTP_XOR_MULT_DOSStub_59a3 {
  strings:
    $key_59a3 = { 0d cb [2] 79 d3 [2] 3e d1 [2] 79 c0 [2] 37 cc [2] 3b c6 [2] 2c cd [2] 37 83 [2] 0a }

  condition:
    any of them
}