rule TTP_XOR_MULT_DOSStub_dd65 {
  strings:
    $key_dd65 = { 89 0d [2] fd 15 [2] ba 17 [2] fd 06 [2] b3 0a [2] bf 00 [2] a8 0b [2] b3 45 [2] 8e }

  condition:
    any of them
}