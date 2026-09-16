rule TTP_XOR_MULT_DOSStub_dd39 {
  strings:
    $key_dd39 = { 89 51 [2] fd 49 [2] ba 4b [2] fd 5a [2] b3 56 [2] bf 5c [2] a8 57 [2] b3 19 [2] 8e }

  condition:
    any of them
}