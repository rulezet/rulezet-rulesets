rule TTP_XOR_MULT_DOSStub_f726 {
  strings:
    $key_f726 = { a3 4e [2] d7 56 [2] 90 54 [2] d7 45 [2] 99 49 [2] 95 43 [2] 82 48 [2] 99 06 [2] a4 }

  condition:
    any of them
}