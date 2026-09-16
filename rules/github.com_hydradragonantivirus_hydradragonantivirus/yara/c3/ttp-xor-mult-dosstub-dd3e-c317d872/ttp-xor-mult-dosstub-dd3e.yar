rule TTP_XOR_MULT_DOSStub_dd3e {
  strings:
    $key_dd3e = { 89 56 [2] fd 4e [2] ba 4c [2] fd 5d [2] b3 51 [2] bf 5b [2] a8 50 [2] b3 1e [2] 8e }

  condition:
    any of them
}