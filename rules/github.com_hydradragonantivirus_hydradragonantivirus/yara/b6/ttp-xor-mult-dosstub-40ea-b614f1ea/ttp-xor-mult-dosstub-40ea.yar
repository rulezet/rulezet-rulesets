rule TTP_XOR_MULT_DOSStub_40ea {
  strings:
    $key_40ea = { 14 82 [2] 60 9a [2] 27 98 [2] 60 89 [2] 2e 85 [2] 22 8f [2] 35 84 [2] 2e ca [2] 13 }

  condition:
    any of them
}