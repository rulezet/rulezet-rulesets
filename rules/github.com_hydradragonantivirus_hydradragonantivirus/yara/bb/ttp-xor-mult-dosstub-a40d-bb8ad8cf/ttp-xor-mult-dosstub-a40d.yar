rule TTP_XOR_MULT_DOSStub_a40d {
  strings:
    $key_a40d = { f0 65 [2] 84 7d [2] c3 7f [2] 84 6e [2] ca 62 [2] c6 68 [2] d1 63 [2] ca 2d [2] f7 }

  condition:
    any of them
}