rule TTP_XOR_MULT_DOSStub_cabf {
  strings:
    $key_cabf = { 9e d7 [2] ea cf [2] ad cd [2] ea dc [2] a4 d0 [2] a8 da [2] bf d1 [2] a4 9f [2] 99 }

  condition:
    any of them
}