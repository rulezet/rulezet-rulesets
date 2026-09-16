rule TTP_XOR_MULT_DOSStub_99ca {
  strings:
    $key_99ca = { cd a2 [2] b9 ba [2] fe b8 [2] b9 a9 [2] f7 a5 [2] fb af [2] ec a4 [2] f7 ea [2] ca }

  condition:
    any of them
}