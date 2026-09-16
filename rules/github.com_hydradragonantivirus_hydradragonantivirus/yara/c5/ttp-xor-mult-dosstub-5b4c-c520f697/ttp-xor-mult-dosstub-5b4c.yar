rule TTP_XOR_MULT_DOSStub_5b4c {
  strings:
    $key_5b4c = { 0f 24 [2] 7b 3c [2] 3c 3e [2] 7b 2f [2] 35 23 [2] 39 29 [2] 2e 22 [2] 35 6c [2] 08 }

  condition:
    any of them
}