rule TTP_XOR_MULT_DOSStub_f611 {
  strings:
    $key_f611 = { a2 79 [2] d6 61 [2] 91 63 [2] d6 72 [2] 98 7e [2] 94 74 [2] 83 7f [2] 98 31 [2] a5 }

  condition:
    any of them
}