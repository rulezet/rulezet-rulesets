rule TTP_XOR_MULT_DOSStub_f552 {
  strings:
    $key_f552 = { a1 3a [2] d5 22 [2] 92 20 [2] d5 31 [2] 9b 3d [2] 97 37 [2] 80 3c [2] 9b 72 [2] a6 }

  condition:
    any of them
}