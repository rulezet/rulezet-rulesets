rule TTP_XOR_MULT_DOSStub_a8d9 {
  strings:
    $key_a8d9 = { fc b1 [2] 88 a9 [2] cf ab [2] 88 ba [2] c6 b6 [2] ca bc [2] dd b7 [2] c6 f9 [2] fb }

  condition:
    any of them
}