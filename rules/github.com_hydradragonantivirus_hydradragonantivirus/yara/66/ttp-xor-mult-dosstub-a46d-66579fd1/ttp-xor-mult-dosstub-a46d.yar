rule TTP_XOR_MULT_DOSStub_a46d {
  strings:
    $key_a46d = { f0 05 [2] 84 1d [2] c3 1f [2] 84 0e [2] ca 02 [2] c6 08 [2] d1 03 [2] ca 4d [2] f7 }

  condition:
    any of them
}