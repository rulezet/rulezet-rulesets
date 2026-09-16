rule TTP_XOR_MULT_DOSStub_dd33 {
  strings:
    $key_dd33 = { 89 5b [2] fd 43 [2] ba 41 [2] fd 50 [2] b3 5c [2] bf 56 [2] a8 5d [2] b3 13 [2] 8e }

  condition:
    any of them
}