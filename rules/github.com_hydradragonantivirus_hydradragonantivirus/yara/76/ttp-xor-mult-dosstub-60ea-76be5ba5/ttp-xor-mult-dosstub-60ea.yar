rule TTP_XOR_MULT_DOSStub_60ea {
  strings:
    $key_60ea = { 34 82 [2] 40 9a [2] 07 98 [2] 40 89 [2] 0e 85 [2] 02 8f [2] 15 84 [2] 0e ca [2] 33 }

  condition:
    any of them
}