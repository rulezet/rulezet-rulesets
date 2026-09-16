rule TTP_XOR_MULT_DOSStub_24ea {
  strings:
    $key_24ea = { 70 82 [2] 04 9a [2] 43 98 [2] 04 89 [2] 4a 85 [2] 46 8f [2] 51 84 [2] 4a ca [2] 77 }

  condition:
    any of them
}