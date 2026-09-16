rule TTP_XOR_MULT_DOSStub_dd02 {
  strings:
    $key_dd02 = { 89 6a [2] fd 72 [2] ba 70 [2] fd 61 [2] b3 6d [2] bf 67 [2] a8 6c [2] b3 22 [2] 8e }

  condition:
    any of them
}