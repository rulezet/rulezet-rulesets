rule TTP_XOR_MULT_DOSStub_dd41 {
  strings:
    $key_dd41 = { 89 29 [2] fd 31 [2] ba 33 [2] fd 22 [2] b3 2e [2] bf 24 [2] a8 2f [2] b3 61 [2] 8e }

  condition:
    any of them
}