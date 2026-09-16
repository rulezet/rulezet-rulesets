rule TTP_XOR_MULT_DOSStub_36ea {
  strings:
    $key_36ea = { 62 82 [2] 16 9a [2] 51 98 [2] 16 89 [2] 58 85 [2] 54 8f [2] 43 84 [2] 58 ca [2] 65 }

  condition:
    any of them
}