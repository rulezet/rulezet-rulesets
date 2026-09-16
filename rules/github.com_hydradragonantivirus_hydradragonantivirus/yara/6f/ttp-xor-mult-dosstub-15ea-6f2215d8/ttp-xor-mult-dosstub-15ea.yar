rule TTP_XOR_MULT_DOSStub_15ea {
  strings:
    $key_15ea = { 41 82 [2] 35 9a [2] 72 98 [2] 35 89 [2] 7b 85 [2] 77 8f [2] 60 84 [2] 7b ca [2] 46 }

  condition:
    any of them
}