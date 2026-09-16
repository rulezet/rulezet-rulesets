rule TTP_XOR_MULT_DOSStub_f7e0 {
  strings:
    $key_f7e0 = { a3 88 [2] d7 90 [2] 90 92 [2] d7 83 [2] 99 8f [2] 95 85 [2] 82 8e [2] 99 c0 [2] a4 }

  condition:
    any of them
}