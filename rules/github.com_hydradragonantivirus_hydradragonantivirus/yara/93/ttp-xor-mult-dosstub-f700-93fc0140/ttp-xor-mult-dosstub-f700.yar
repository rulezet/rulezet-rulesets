rule TTP_XOR_MULT_DOSStub_f700 {
  strings:
    $key_f700 = { a3 68 [2] d7 70 [2] 90 72 [2] d7 63 [2] 99 6f [2] 95 65 [2] 82 6e [2] 99 20 [2] a4 }

  condition:
    any of them
}