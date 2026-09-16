rule TTP_XOR_MULT_DOSStub_dd0b {
  strings:
    $key_dd0b = { 89 63 [2] fd 7b [2] ba 79 [2] fd 68 [2] b3 64 [2] bf 6e [2] a8 65 [2] b3 2b [2] 8e }

  condition:
    any of them
}