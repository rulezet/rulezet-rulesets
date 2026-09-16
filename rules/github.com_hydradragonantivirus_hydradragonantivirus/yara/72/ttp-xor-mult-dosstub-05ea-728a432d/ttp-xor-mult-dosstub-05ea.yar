rule TTP_XOR_MULT_DOSStub_05ea {
  strings:
    $key_05ea = { 51 82 [2] 25 9a [2] 62 98 [2] 25 89 [2] 6b 85 [2] 67 8f [2] 70 84 [2] 6b ca [2] 56 }

  condition:
    any of them
}