rule TTP_XOR_MULT_DOSStub_0e10 {
  strings:
    $key_0e10 = { 5a 78 [2] 2e 60 [2] 69 62 [2] 2e 73 [2] 60 7f [2] 6c 75 [2] 7b 7e [2] 60 30 [2] 5d }

  condition:
    any of them
}