rule TTP_XOR_MULT_DOSStub_17ea {
  strings:
    $key_17ea = { 43 82 [2] 37 9a [2] 70 98 [2] 37 89 [2] 79 85 [2] 75 8f [2] 62 84 [2] 79 ca [2] 44 }

  condition:
    any of them
}