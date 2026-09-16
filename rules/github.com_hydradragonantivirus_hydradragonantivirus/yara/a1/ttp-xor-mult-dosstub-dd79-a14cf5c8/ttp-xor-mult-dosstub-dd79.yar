rule TTP_XOR_MULT_DOSStub_dd79 {
  strings:
    $key_dd79 = { 89 11 [2] fd 09 [2] ba 0b [2] fd 1a [2] b3 16 [2] bf 1c [2] a8 17 [2] b3 59 [2] 8e }

  condition:
    any of them
}