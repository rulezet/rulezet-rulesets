rule TTP_XOR_MULT_DOSStub_5b50 {
  strings:
    $key_5b50 = { 0f 38 [2] 7b 20 [2] 3c 22 [2] 7b 33 [2] 35 3f [2] 39 35 [2] 2e 3e [2] 35 70 [2] 08 }

  condition:
    any of them
}