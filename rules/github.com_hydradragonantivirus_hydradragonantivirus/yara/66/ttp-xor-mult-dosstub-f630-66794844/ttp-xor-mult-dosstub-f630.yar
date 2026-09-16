rule TTP_XOR_MULT_DOSStub_f630 {
  strings:
    $key_f630 = { a2 58 [2] d6 40 [2] 91 42 [2] d6 53 [2] 98 5f [2] 94 55 [2] 83 5e [2] 98 10 [2] a5 }

  condition:
    any of them
}