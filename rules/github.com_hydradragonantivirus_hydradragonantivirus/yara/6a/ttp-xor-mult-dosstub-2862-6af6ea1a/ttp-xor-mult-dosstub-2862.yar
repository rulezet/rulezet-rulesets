rule TTP_XOR_MULT_DOSStub_2862 {
  strings:
    $key_2862 = { 7c 0a [2] 08 12 [2] 4f 10 [2] 08 01 [2] 46 0d [2] 4a 07 [2] 5d 0c [2] 46 42 [2] 7b }

  condition:
    any of them
}