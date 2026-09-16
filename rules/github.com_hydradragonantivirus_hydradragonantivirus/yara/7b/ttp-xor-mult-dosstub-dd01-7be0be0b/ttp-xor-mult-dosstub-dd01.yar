rule TTP_XOR_MULT_DOSStub_dd01 {
  strings:
    $key_dd01 = { 89 69 [2] fd 71 [2] ba 73 [2] fd 62 [2] b3 6e [2] bf 64 [2] a8 6f [2] b3 21 [2] 8e }

  condition:
    any of them
}