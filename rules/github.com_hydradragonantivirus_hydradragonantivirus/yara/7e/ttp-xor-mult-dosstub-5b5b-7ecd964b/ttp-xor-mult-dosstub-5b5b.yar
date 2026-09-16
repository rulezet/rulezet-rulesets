rule TTP_XOR_MULT_DOSStub_5b5b {
  strings:
    $key_5b5b = { 0f 33 [2] 7b 2b [2] 3c 29 [2] 7b 38 [2] 35 34 [2] 39 3e [2] 2e 35 [2] 35 7b [2] 08 }

  condition:
    any of them
}