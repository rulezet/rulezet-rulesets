rule TTP_XOR_MULT_DOSStub_56ea {
  strings:
    $key_56ea = { 02 82 [2] 76 9a [2] 31 98 [2] 76 89 [2] 38 85 [2] 34 8f [2] 23 84 [2] 38 ca [2] 05 }

  condition:
    any of them
}