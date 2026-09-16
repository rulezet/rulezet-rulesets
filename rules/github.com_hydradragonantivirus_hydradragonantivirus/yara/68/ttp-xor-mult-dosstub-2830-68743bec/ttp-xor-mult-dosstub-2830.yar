rule TTP_XOR_MULT_DOSStub_2830 {
  strings:
    $key_2830 = { 7c 58 [2] 08 40 [2] 4f 42 [2] 08 53 [2] 46 5f [2] 4a 55 [2] 5d 5e [2] 46 10 [2] 7b }

  condition:
    any of them
}