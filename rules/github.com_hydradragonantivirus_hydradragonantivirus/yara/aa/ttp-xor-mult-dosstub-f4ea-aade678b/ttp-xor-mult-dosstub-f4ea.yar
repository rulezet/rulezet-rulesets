rule TTP_XOR_MULT_DOSStub_f4ea {
  strings:
    $key_f4ea = { a0 82 [2] d4 9a [2] 93 98 [2] d4 89 [2] 9a 85 [2] 96 8f [2] 81 84 [2] 9a ca [2] a7 }

  condition:
    any of them
}