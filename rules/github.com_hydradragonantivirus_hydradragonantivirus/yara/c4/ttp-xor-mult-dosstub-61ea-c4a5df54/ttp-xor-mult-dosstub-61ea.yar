rule TTP_XOR_MULT_DOSStub_61ea {
  strings:
    $key_61ea = { 35 82 [2] 41 9a [2] 06 98 [2] 41 89 [2] 0f 85 [2] 03 8f [2] 14 84 [2] 0f ca [2] 32 }

  condition:
    any of them
}