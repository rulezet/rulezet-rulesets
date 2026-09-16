rule TTP_XOR_MULT_DOSStub_a8d0 {
  strings:
    $key_a8d0 = { fc b8 [2] 88 a0 [2] cf a2 [2] 88 b3 [2] c6 bf [2] ca b5 [2] dd be [2] c6 f0 [2] fb }

  condition:
    any of them
}