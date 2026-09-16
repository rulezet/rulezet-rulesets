rule TTP_XOR_MULT_DOSStub_dd4b {
  strings:
    $key_dd4b = { 89 23 [2] fd 3b [2] ba 39 [2] fd 28 [2] b3 24 [2] bf 2e [2] a8 25 [2] b3 6b [2] 8e }

  condition:
    any of them
}