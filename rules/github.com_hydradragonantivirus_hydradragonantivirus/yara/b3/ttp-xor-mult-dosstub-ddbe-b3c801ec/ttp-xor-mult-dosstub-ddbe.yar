rule TTP_XOR_MULT_DOSStub_ddbe {
  strings:
    $key_ddbe = { 89 d6 [2] fd ce [2] ba cc [2] fd dd [2] b3 d1 [2] bf db [2] a8 d0 [2] b3 9e [2] 8e }

  condition:
    any of them
}