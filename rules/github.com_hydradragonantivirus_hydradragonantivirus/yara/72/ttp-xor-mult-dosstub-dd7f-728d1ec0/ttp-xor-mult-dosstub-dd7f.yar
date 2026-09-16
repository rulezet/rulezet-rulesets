rule TTP_XOR_MULT_DOSStub_dd7f {
  strings:
    $key_dd7f = { 89 17 [2] fd 0f [2] ba 0d [2] fd 1c [2] b3 10 [2] bf 1a [2] a8 11 [2] b3 5f [2] 8e }

  condition:
    any of them
}