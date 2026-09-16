rule TTP_XOR_MULT_DOSStub_f066 {
  strings:
    $key_f066 = { a4 0e [2] d0 16 [2] 97 14 [2] d0 05 [2] 9e 09 [2] 92 03 [2] 85 08 [2] 9e 46 [2] a3 }

  condition:
    any of them
}