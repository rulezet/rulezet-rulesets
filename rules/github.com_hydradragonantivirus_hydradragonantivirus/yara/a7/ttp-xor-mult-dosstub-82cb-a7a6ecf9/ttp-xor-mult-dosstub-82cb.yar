rule TTP_XOR_MULT_DOSStub_82cb {
  strings:
    $key_82cb = { d6 a3 [2] a2 bb [2] e5 b9 [2] a2 a8 [2] ec a4 [2] e0 ae [2] f7 a5 [2] ec eb [2] d1 }

  condition:
    any of them
}