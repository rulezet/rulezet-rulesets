rule TTP_XOR_MULT_DOSStub_dd0e {
  strings:
    $key_dd0e = { 89 66 [2] fd 7e [2] ba 7c [2] fd 6d [2] b3 61 [2] bf 6b [2] a8 60 [2] b3 2e [2] 8e }

  condition:
    any of them
}