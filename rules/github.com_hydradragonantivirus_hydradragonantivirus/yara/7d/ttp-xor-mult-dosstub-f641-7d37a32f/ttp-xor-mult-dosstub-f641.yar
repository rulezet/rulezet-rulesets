rule TTP_XOR_MULT_DOSStub_f641 {
  strings:
    $key_f641 = { a2 29 [2] d6 31 [2] 91 33 [2] d6 22 [2] 98 2e [2] 94 24 [2] 83 2f [2] 98 61 [2] a5 }

  condition:
    any of them
}