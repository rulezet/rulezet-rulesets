rule TTP_XOR_MULT_DOSStub_f267 {
  strings:
    $key_f267 = { a6 0f [2] d2 17 [2] 95 15 [2] d2 04 [2] 9c 08 [2] 90 02 [2] 87 09 [2] 9c 47 [2] a1 }

  condition:
    any of them
}