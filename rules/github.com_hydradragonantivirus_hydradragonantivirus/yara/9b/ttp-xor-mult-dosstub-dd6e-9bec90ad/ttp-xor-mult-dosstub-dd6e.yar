rule TTP_XOR_MULT_DOSStub_dd6e {
  strings:
    $key_dd6e = { 89 06 [2] fd 1e [2] ba 1c [2] fd 0d [2] b3 01 [2] bf 0b [2] a8 00 [2] b3 4e [2] 8e }

  condition:
    any of them
}