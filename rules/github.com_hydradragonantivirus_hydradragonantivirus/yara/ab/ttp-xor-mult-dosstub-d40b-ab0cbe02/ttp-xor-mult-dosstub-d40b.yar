rule TTP_XOR_MULT_DOSStub_d40b {
  strings:
    $key_d40b = { 80 63 [2] f4 7b [2] b3 79 [2] f4 68 [2] ba 64 [2] b6 6e [2] a1 65 [2] ba 2b [2] 87 }

  condition:
    any of them
}