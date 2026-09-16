rule TTP_XOR_MULT_DOSStub_41ea {
  strings:
    $key_41ea = { 15 82 [2] 61 9a [2] 26 98 [2] 61 89 [2] 2f 85 [2] 23 8f [2] 34 84 [2] 2f ca [2] 12 }

  condition:
    any of them
}