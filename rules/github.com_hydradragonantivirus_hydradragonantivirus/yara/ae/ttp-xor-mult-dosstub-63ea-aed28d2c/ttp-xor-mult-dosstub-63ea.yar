rule TTP_XOR_MULT_DOSStub_63ea {
  strings:
    $key_63ea = { 37 82 [2] 43 9a [2] 04 98 [2] 43 89 [2] 0d 85 [2] 01 8f [2] 16 84 [2] 0d ca [2] 30 }

  condition:
    any of them
}