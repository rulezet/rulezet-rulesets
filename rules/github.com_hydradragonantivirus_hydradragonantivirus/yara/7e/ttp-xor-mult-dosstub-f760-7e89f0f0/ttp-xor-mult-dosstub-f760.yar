rule TTP_XOR_MULT_DOSStub_f760 {
  strings:
    $key_f760 = { a3 08 [2] d7 10 [2] 90 12 [2] d7 03 [2] 99 0f [2] 95 05 [2] 82 0e [2] 99 40 [2] a4 }

  condition:
    any of them
}