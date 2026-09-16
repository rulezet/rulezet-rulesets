rule TTP_XOR_MULT_DOSStub_dabf {
  strings:
    $key_dabf = { 8e d7 [2] fa cf [2] bd cd [2] fa dc [2] b4 d0 [2] b8 da [2] af d1 [2] b4 9f [2] 89 }

  condition:
    any of them
}