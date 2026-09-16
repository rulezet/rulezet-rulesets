rule TTP_XOR_MULT_DOSStub_f647 {
  strings:
    $key_f647 = { a2 2f [2] d6 37 [2] 91 35 [2] d6 24 [2] 98 28 [2] 94 22 [2] 83 29 [2] 98 67 [2] a5 }

  condition:
    any of them
}