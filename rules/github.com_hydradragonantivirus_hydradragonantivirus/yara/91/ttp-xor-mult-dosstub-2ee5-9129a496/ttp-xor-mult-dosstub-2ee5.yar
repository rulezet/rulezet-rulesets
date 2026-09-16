rule TTP_XOR_MULT_DOSStub_2ee5 {
  strings:
    $key_2ee5 = { 7a 8d [2] 0e 95 [2] 49 97 [2] 0e 86 [2] 40 8a [2] 4c 80 [2] 5b 8b [2] 40 c5 [2] 7d }

  condition:
    any of them
}