rule TTP_XOR_MULT_DOSStub_f631 {
  strings:
    $key_f631 = { a2 59 [2] d6 41 [2] 91 43 [2] d6 52 [2] 98 5e [2] 94 54 [2] 83 5f [2] 98 11 [2] a5 }

  condition:
    any of them
}