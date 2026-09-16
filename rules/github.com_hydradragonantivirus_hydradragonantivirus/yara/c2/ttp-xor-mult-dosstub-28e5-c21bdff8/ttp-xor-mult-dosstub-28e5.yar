rule TTP_XOR_MULT_DOSStub_28e5 {
  strings:
    $key_28e5 = { 7c 8d [2] 08 95 [2] 4f 97 [2] 08 86 [2] 46 8a [2] 4a 80 [2] 5d 8b [2] 46 c5 [2] 7b }

  condition:
    any of them
}