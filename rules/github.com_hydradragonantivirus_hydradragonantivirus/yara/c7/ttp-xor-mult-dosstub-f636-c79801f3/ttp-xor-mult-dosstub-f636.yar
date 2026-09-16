rule TTP_XOR_MULT_DOSStub_f636 {
  strings:
    $key_f636 = { a2 5e [2] d6 46 [2] 91 44 [2] d6 55 [2] 98 59 [2] 94 53 [2] 83 58 [2] 98 16 [2] a5 }

  condition:
    any of them
}