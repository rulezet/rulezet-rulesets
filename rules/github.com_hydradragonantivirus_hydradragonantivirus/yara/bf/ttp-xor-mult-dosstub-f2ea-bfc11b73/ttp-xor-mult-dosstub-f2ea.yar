rule TTP_XOR_MULT_DOSStub_f2ea {
  strings:
    $key_f2ea = { a6 82 [2] d2 9a [2] 95 98 [2] d2 89 [2] 9c 85 [2] 90 8f [2] 87 84 [2] 9c ca [2] a1 }

  condition:
    any of them
}