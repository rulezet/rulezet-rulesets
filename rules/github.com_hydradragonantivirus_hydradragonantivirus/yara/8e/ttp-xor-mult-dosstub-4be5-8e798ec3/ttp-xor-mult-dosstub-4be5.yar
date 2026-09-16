rule TTP_XOR_MULT_DOSStub_4be5 {
  strings:
    $key_4be5 = { 1f 8d [2] 6b 95 [2] 2c 97 [2] 6b 86 [2] 25 8a [2] 29 80 [2] 3e 8b [2] 25 c5 [2] 18 }

  condition:
    any of them
}