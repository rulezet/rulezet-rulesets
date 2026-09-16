rule TTP_XOR_MULT_DOSStub_205b {
  strings:
    $key_205b = { 74 33 [2] 00 2b [2] 47 29 [2] 00 38 [2] 4e 34 [2] 42 3e [2] 55 35 [2] 4e 7b [2] 73 }

  condition:
    any of them
}