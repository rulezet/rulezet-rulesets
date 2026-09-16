rule TTP_XOR_MULT_DOSStub_19a3 {
  strings:
    $key_19a3 = { 4d cb [2] 39 d3 [2] 7e d1 [2] 39 c0 [2] 77 cc [2] 7b c6 [2] 6c cd [2] 77 83 [2] 4a }

  condition:
    any of them
}