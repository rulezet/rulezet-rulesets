rule TTP_XOR_MULT_DOSStub_3ce5 {
  strings:
    $key_3ce5 = { 68 8d [2] 1c 95 [2] 5b 97 [2] 1c 86 [2] 52 8a [2] 5e 80 [2] 49 8b [2] 52 c5 [2] 6f }

  condition:
    any of them
}