rule TTP_XOR_MULT_DOSStub_5e15 {
  strings:
    $key_5e15 = { 0a 7d [2] 7e 65 [2] 39 67 [2] 7e 76 [2] 30 7a [2] 3c 70 [2] 2b 7b [2] 30 35 [2] 0d }

  condition:
    any of them
}