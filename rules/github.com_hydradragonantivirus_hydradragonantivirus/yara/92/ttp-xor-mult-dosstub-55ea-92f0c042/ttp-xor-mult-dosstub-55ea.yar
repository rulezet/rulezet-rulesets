rule TTP_XOR_MULT_DOSStub_55ea {
  strings:
    $key_55ea = { 01 82 [2] 75 9a [2] 32 98 [2] 75 89 [2] 3b 85 [2] 37 8f [2] 20 84 [2] 3b ca [2] 06 }

  condition:
    any of them
}