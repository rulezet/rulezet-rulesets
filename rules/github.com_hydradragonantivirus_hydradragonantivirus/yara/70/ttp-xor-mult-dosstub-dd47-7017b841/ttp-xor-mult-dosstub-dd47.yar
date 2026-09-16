rule TTP_XOR_MULT_DOSStub_dd47 {
  strings:
    $key_dd47 = { 89 2f [2] fd 37 [2] ba 35 [2] fd 24 [2] b3 28 [2] bf 22 [2] a8 29 [2] b3 67 [2] 8e }

  condition:
    any of them
}