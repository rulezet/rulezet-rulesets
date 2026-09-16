rule TTP_XOR_MULT_DOSStub_42fc {
  strings:
    $key_42fc = { 16 94 [2] 62 8c [2] 25 8e [2] 62 9f [2] 2c 93 [2] 20 99 [2] 37 92 [2] 2c dc [2] 11 }

  condition:
    any of them
}