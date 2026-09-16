rule TTP_XOR_MULT_DOSStub_5b7c {
  strings:
    $key_5b7c = { 0f 14 [2] 7b 0c [2] 3c 0e [2] 7b 1f [2] 35 13 [2] 39 19 [2] 2e 12 [2] 35 5c [2] 08 }

  condition:
    any of them
}