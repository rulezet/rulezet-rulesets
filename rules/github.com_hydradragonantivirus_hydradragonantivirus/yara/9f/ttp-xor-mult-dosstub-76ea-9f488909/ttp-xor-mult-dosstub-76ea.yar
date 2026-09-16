rule TTP_XOR_MULT_DOSStub_76ea {
  strings:
    $key_76ea = { 22 82 [2] 56 9a [2] 11 98 [2] 56 89 [2] 18 85 [2] 14 8f [2] 03 84 [2] 18 ca [2] 25 }

  condition:
    any of them
}