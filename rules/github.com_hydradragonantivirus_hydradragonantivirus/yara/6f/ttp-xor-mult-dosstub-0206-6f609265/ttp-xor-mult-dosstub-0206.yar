rule TTP_XOR_MULT_DOSStub_0206 {
  strings:
    $key_0206 = { 56 6e [2] 22 76 [2] 65 74 [2] 22 65 [2] 6c 69 [2] 60 63 [2] 77 68 [2] 6c 26 [2] 51 }

  condition:
    any of them
}