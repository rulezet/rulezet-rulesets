rule TTP_XOR_MULT_DOSStub_32ea {
  strings:
    $key_32ea = { 66 82 [2] 12 9a [2] 55 98 [2] 12 89 [2] 5c 85 [2] 50 8f [2] 47 84 [2] 5c ca [2] 61 }

  condition:
    any of them
}