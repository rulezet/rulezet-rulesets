rule TTP_XOR_MULT_DOSStub_2817 {
  strings:
    $key_2817 = { 7c 7f [2] 08 67 [2] 4f 65 [2] 08 74 [2] 46 78 [2] 4a 72 [2] 5d 79 [2] 46 37 [2] 7b }

  condition:
    any of them
}