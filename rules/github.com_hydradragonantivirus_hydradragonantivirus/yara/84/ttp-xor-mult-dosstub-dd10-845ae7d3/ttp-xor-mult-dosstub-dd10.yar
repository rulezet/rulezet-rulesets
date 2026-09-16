rule TTP_XOR_MULT_DOSStub_dd10 {
  strings:
    $key_dd10 = { 89 78 [2] fd 60 [2] ba 62 [2] fd 73 [2] b3 7f [2] bf 75 [2] a8 7e [2] b3 30 [2] 8e }

  condition:
    any of them
}