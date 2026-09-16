rule TTP_XOR_MULT_DOSStub_dd48 {
  strings:
    $key_dd48 = { 89 20 [2] fd 38 [2] ba 3a [2] fd 2b [2] b3 27 [2] bf 2d [2] a8 26 [2] b3 68 [2] 8e }

  condition:
    any of them
}