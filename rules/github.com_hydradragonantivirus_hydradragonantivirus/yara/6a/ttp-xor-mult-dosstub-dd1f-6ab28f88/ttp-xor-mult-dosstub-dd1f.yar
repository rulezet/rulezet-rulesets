rule TTP_XOR_MULT_DOSStub_dd1f {
  strings:
    $key_dd1f = { 89 77 [2] fd 6f [2] ba 6d [2] fd 7c [2] b3 70 [2] bf 7a [2] a8 71 [2] b3 3f [2] 8e }

  condition:
    any of them
}