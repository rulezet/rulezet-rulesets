rule TTP_XOR_MULT_DOSStub_cfae {
  strings:
    $key_cfae = { 9b c6 [2] ef de [2] a8 dc [2] ef cd [2] a1 c1 [2] ad cb [2] ba c0 [2] a1 8e [2] 9c }

  condition:
    any of them
}