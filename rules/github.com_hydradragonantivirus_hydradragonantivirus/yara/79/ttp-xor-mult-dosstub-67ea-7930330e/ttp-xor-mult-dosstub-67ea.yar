rule TTP_XOR_MULT_DOSStub_67ea {
  strings:
    $key_67ea = { 33 82 [2] 47 9a [2] 00 98 [2] 47 89 [2] 09 85 [2] 05 8f [2] 12 84 [2] 09 ca [2] 34 }

  condition:
    any of them
}