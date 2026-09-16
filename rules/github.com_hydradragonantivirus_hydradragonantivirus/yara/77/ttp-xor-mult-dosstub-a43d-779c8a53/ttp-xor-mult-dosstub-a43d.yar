rule TTP_XOR_MULT_DOSStub_a43d {
  strings:
    $key_a43d = { f0 55 [2] 84 4d [2] c3 4f [2] 84 5e [2] ca 52 [2] c6 58 [2] d1 53 [2] ca 1d [2] f7 }

  condition:
    any of them
}