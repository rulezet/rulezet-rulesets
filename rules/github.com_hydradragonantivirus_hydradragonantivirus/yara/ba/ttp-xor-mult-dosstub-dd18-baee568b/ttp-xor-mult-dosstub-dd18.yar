rule TTP_XOR_MULT_DOSStub_dd18 {
  strings:
    $key_dd18 = { 89 70 [2] fd 68 [2] ba 6a [2] fd 7b [2] b3 77 [2] bf 7d [2] a8 76 [2] b3 38 [2] 8e }

  condition:
    any of them
}