rule TTP_XOR_MULT_DOSStub_1e10 {
  strings:
    $key_1e10 = { 4a 78 [2] 3e 60 [2] 79 62 [2] 3e 73 [2] 70 7f [2] 7c 75 [2] 6b 7e [2] 70 30 [2] 4d }

  condition:
    any of them
}