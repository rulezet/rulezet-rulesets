rule TTP_XOR_MULT_DOSStub_52ea {
  strings:
    $key_52ea = { 06 82 [2] 72 9a [2] 35 98 [2] 72 89 [2] 3c 85 [2] 30 8f [2] 27 84 [2] 3c ca [2] 01 }

  condition:
    any of them
}