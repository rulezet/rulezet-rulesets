rule TTP_XOR_MULT_DOSStub_dd3c {
  strings:
    $key_dd3c = { 89 54 [2] fd 4c [2] ba 4e [2] fd 5f [2] b3 53 [2] bf 59 [2] a8 52 [2] b3 1c [2] 8e }

  condition:
    any of them
}