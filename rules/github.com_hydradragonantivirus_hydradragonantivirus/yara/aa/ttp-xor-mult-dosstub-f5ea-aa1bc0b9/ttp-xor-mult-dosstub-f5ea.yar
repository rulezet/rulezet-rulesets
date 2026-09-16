rule TTP_XOR_MULT_DOSStub_f5ea {
  strings:
    $key_f5ea = { a1 82 [2] d5 9a [2] 92 98 [2] d5 89 [2] 9b 85 [2] 97 8f [2] 80 84 [2] 9b ca [2] a6 }

  condition:
    any of them
}