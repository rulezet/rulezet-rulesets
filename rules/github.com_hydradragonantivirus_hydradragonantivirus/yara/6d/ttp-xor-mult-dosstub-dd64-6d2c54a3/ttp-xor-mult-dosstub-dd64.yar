rule TTP_XOR_MULT_DOSStub_dd64 {
  strings:
    $key_dd64 = { 89 0c [2] fd 14 [2] ba 16 [2] fd 07 [2] b3 0b [2] bf 01 [2] a8 0a [2] b3 44 [2] 8e }

  condition:
    any of them
}