rule TTP_XOR_MULT_DOSStub_5be5 {
  strings:
    $key_5be5 = { 0f 8d [2] 7b 95 [2] 3c 97 [2] 7b 86 [2] 35 8a [2] 39 80 [2] 2e 8b [2] 35 c5 [2] 08 }

  condition:
    any of them
}