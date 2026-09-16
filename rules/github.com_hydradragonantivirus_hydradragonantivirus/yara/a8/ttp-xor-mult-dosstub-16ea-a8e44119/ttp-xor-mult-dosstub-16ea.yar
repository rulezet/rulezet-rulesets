rule TTP_XOR_MULT_DOSStub_16ea {
  strings:
    $key_16ea = { 42 82 [2] 36 9a [2] 71 98 [2] 36 89 [2] 78 85 [2] 74 8f [2] 63 84 [2] 78 ca [2] 45 }

  condition:
    any of them
}