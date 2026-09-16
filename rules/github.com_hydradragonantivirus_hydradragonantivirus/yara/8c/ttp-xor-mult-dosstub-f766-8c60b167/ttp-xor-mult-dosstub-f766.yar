rule TTP_XOR_MULT_DOSStub_f766 {
  strings:
    $key_f766 = { a3 0e [2] d7 16 [2] 90 14 [2] d7 05 [2] 99 09 [2] 95 03 [2] 82 08 [2] 99 46 [2] a4 }

  condition:
    any of them
}