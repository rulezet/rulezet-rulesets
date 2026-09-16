rule TTP_XOR_MULT_DOSStub_e7ea {
  strings:
    $key_e7ea = { b3 82 [2] c7 9a [2] 80 98 [2] c7 89 [2] 89 85 [2] 85 8f [2] 92 84 [2] 89 ca [2] b4 }

  condition:
    any of them
}