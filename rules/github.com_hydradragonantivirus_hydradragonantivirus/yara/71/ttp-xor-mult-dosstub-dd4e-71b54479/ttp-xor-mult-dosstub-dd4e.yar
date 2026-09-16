rule TTP_XOR_MULT_DOSStub_dd4e {
  strings:
    $key_dd4e = { 89 26 [2] fd 3e [2] ba 3c [2] fd 2d [2] b3 21 [2] bf 2b [2] a8 20 [2] b3 6e [2] 8e }

  condition:
    any of them
}