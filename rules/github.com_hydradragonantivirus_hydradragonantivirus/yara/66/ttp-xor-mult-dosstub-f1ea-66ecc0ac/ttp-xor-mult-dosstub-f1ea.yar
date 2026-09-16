rule TTP_XOR_MULT_DOSStub_f1ea {
  strings:
    $key_f1ea = { a5 82 [2] d1 9a [2] 96 98 [2] d1 89 [2] 9f 85 [2] 93 8f [2] 84 84 [2] 9f ca [2] a2 }

  condition:
    any of them
}