rule TTP_XOR_MULT_DOSStub_a43b {
  strings:
    $key_a43b = { f0 53 [2] 84 4b [2] c3 49 [2] 84 58 [2] ca 54 [2] c6 5e [2] d1 55 [2] ca 1b [2] f7 }

  condition:
    any of them
}