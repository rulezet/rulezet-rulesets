rule TTP_XOR_MULT_DOSStub_dd3f {
  strings:
    $key_dd3f = { 89 57 [2] fd 4f [2] ba 4d [2] fd 5c [2] b3 50 [2] bf 5a [2] a8 51 [2] b3 1f [2] 8e }

  condition:
    any of them
}