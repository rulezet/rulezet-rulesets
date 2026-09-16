rule TTP_XOR_MULT_DOSStub_f661 {
  strings:
    $key_f661 = { a2 09 [2] d6 11 [2] 91 13 [2] d6 02 [2] 98 0e [2] 94 04 [2] 83 0f [2] 98 41 [2] a5 }

  condition:
    any of them
}