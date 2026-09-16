rule TTP_XOR_MULT_DOSStub_f670 {
  strings:
    $key_f670 = { a2 18 [2] d6 00 [2] 91 02 [2] d6 13 [2] 98 1f [2] 94 15 [2] 83 1e [2] 98 50 [2] a5 }

  condition:
    any of them
}