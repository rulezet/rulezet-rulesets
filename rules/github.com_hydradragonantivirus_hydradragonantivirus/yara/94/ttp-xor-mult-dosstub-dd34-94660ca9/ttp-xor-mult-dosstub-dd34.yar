rule TTP_XOR_MULT_DOSStub_dd34 {
  strings:
    $key_dd34 = { 89 5c [2] fd 44 [2] ba 46 [2] fd 57 [2] b3 5b [2] bf 51 [2] a8 5a [2] b3 14 [2] 8e }

  condition:
    any of them
}