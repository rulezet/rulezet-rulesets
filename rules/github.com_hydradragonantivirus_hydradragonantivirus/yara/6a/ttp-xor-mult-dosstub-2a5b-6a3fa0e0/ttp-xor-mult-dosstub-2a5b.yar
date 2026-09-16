rule TTP_XOR_MULT_DOSStub_2a5b {
  strings:
    $key_2a5b = { 7e 33 [2] 0a 2b [2] 4d 29 [2] 0a 38 [2] 44 34 [2] 48 3e [2] 5f 35 [2] 44 7b [2] 79 }

  condition:
    any of them
}