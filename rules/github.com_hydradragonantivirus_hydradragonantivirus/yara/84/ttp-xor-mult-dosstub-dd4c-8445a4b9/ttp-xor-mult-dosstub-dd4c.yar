rule TTP_XOR_MULT_DOSStub_dd4c {
  strings:
    $key_dd4c = { 89 24 [2] fd 3c [2] ba 3e [2] fd 2f [2] b3 23 [2] bf 29 [2] a8 22 [2] b3 6c [2] 8e }

  condition:
    any of them
}