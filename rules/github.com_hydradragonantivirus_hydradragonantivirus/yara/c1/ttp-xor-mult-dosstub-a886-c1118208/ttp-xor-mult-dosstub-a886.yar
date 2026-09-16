rule TTP_XOR_MULT_DOSStub_a886 {
  strings:
    $key_a886 = { fc ee [2] 88 f6 [2] cf f4 [2] 88 e5 [2] c6 e9 [2] ca e3 [2] dd e8 [2] c6 a6 [2] fb }

  condition:
    any of them
}