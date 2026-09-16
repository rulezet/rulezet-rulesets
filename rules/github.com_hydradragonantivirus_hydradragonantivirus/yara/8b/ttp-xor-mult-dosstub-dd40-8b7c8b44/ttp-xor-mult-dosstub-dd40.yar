rule TTP_XOR_MULT_DOSStub_dd40 {
  strings:
    $key_dd40 = { 89 28 [2] fd 30 [2] ba 32 [2] fd 23 [2] b3 2f [2] bf 25 [2] a8 2e [2] b3 60 [2] 8e }

  condition:
    any of them
}