rule TTP_XOR_MULT_DOSStub_a70d {
  strings:
    $key_a70d = { f3 65 [2] 87 7d [2] c0 7f [2] 87 6e [2] c9 62 [2] c5 68 [2] d2 63 [2] c9 2d [2] f4 }

  condition:
    any of them
}