rule TTP_XOR_MULT_DOSStub_10ea {
  strings:
    $key_10ea = { 44 82 [2] 30 9a [2] 77 98 [2] 30 89 [2] 7e 85 [2] 72 8f [2] 65 84 [2] 7e ca [2] 43 }

  condition:
    any of them
}