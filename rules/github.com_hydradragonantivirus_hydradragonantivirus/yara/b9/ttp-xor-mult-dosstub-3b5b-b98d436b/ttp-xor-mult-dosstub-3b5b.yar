rule TTP_XOR_MULT_DOSStub_3b5b {
  strings:
    $key_3b5b = { 6f 33 [2] 1b 2b [2] 5c 29 [2] 1b 38 [2] 55 34 [2] 59 3e [2] 4e 35 [2] 55 7b [2] 68 }

  condition:
    any of them
}