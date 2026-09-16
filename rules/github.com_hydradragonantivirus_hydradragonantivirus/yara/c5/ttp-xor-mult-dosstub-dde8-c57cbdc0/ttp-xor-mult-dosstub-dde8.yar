rule TTP_XOR_MULT_DOSStub_dde8 {
  strings:
    $key_dde8 = { 89 80 [2] fd 98 [2] ba 9a [2] fd 8b [2] b3 87 [2] bf 8d [2] a8 86 [2] b3 c8 [2] 8e }

  condition:
    any of them
}