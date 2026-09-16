rule TTP_XOR_MULT_DOSStub_f650 {
  strings:
    $key_f650 = { a2 38 [2] d6 20 [2] 91 22 [2] d6 33 [2] 98 3f [2] 94 35 [2] 83 3e [2] 98 70 [2] a5 }

  condition:
    any of them
}