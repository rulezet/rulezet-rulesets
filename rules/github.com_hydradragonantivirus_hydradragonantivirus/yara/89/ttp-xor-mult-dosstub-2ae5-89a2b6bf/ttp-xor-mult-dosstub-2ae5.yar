rule TTP_XOR_MULT_DOSStub_2ae5 {
  strings:
    $key_2ae5 = { 7e 8d [2] 0a 95 [2] 4d 97 [2] 0a 86 [2] 44 8a [2] 48 80 [2] 5f 8b [2] 44 c5 [2] 79 }

  condition:
    any of them
}