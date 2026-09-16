rule TTP_XOR_MULT_DOSStub_dd57 {
  strings:
    $key_dd57 = { 89 3f [2] fd 27 [2] ba 25 [2] fd 34 [2] b3 38 [2] bf 32 [2] a8 39 [2] b3 77 [2] 8e }

  condition:
    any of them
}