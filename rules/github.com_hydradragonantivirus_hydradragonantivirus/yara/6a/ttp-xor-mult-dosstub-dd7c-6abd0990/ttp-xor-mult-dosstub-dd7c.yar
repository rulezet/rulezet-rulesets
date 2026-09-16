rule TTP_XOR_MULT_DOSStub_dd7c {
  strings:
    $key_dd7c = { 89 14 [2] fd 0c [2] ba 0e [2] fd 1f [2] b3 13 [2] bf 19 [2] a8 12 [2] b3 5c [2] 8e }

  condition:
    any of them
}