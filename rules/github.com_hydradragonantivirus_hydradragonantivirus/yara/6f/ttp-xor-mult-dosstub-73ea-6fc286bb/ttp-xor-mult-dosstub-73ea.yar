rule TTP_XOR_MULT_DOSStub_73ea {
  strings:
    $key_73ea = { 27 82 [2] 53 9a [2] 14 98 [2] 53 89 [2] 1d 85 [2] 11 8f [2] 06 84 [2] 1d ca [2] 20 }

  condition:
    any of them
}