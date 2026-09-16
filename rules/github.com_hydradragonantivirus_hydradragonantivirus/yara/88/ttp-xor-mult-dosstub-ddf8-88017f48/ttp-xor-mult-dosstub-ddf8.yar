rule TTP_XOR_MULT_DOSStub_ddf8 {
  strings:
    $key_ddf8 = { 89 90 [2] fd 88 [2] ba 8a [2] fd 9b [2] b3 97 [2] bf 9d [2] a8 96 [2] b3 d8 [2] 8e }

  condition:
    any of them
}