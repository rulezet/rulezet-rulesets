rule TTP_XOR_MULT_DOSStub_4ce5 {
  strings:
    $key_4ce5 = { 18 8d [2] 6c 95 [2] 2b 97 [2] 6c 86 [2] 22 8a [2] 2e 80 [2] 39 8b [2] 22 c5 [2] 1f }

  condition:
    any of them
}