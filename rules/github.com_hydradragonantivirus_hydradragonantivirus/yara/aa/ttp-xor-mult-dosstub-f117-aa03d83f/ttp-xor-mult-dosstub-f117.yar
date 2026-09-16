rule TTP_XOR_MULT_DOSStub_f117 {
  strings:
    $key_f117 = { a5 7f [2] d1 67 [2] 96 65 [2] d1 74 [2] 9f 78 [2] 93 72 [2] 84 79 [2] 9f 37 [2] a2 }

  condition:
    any of them
}