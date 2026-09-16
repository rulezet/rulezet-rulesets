rule TTP_XOR_MULT_DOSStub_dde0 {
  strings:
    $key_dde0 = { 89 88 [2] fd 90 [2] ba 92 [2] fd 83 [2] b3 8f [2] bf 85 [2] a8 8e [2] b3 c0 [2] 8e }

  condition:
    any of them
}