rule TTP_XOR_MULT_DOSStub_dd35 {
  strings:
    $key_dd35 = { 89 5d [2] fd 45 [2] ba 47 [2] fd 56 [2] b3 5a [2] bf 50 [2] a8 5b [2] b3 15 [2] 8e }

  condition:
    any of them
}