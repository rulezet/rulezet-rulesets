rule TTP_XOR_MULT_DOSStub_f676 {
  strings:
    $key_f676 = { a2 1e [2] d6 06 [2] 91 04 [2] d6 15 [2] 98 19 [2] 94 13 [2] 83 18 [2] 98 56 [2] a5 }

  condition:
    any of them
}