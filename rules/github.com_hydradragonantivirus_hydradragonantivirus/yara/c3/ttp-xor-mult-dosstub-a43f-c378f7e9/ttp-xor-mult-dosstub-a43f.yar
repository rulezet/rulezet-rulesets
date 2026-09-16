rule TTP_XOR_MULT_DOSStub_a43f {
  strings:
    $key_a43f = { f0 57 [2] 84 4f [2] c3 4d [2] 84 5c [2] ca 50 [2] c6 5a [2] d1 51 [2] ca 1f [2] f7 }

  condition:
    any of them
}