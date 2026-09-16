rule TTP_XOR_MULT_DOSStub_02ea {
  strings:
    $key_02ea = { 56 82 [2] 22 9a [2] 65 98 [2] 22 89 [2] 6c 85 [2] 60 8f [2] 77 84 [2] 6c ca [2] 51 }

  condition:
    any of them
}