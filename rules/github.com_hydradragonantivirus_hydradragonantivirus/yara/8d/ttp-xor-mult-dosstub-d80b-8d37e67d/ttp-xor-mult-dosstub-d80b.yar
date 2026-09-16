rule TTP_XOR_MULT_DOSStub_d80b {
  strings:
    $key_d80b = { 8c 63 [2] f8 7b [2] bf 79 [2] f8 68 [2] b6 64 [2] ba 6e [2] ad 65 [2] b6 2b [2] 8b }

  condition:
    any of them
}