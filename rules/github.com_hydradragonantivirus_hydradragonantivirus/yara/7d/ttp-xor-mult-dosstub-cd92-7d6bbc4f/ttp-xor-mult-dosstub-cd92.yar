rule TTP_XOR_MULT_DOSStub_cd92 {
  strings:
    $key_cd92 = { 99 fa [2] ed e2 [2] aa e0 [2] ed f1 [2] a3 fd [2] af f7 [2] b8 fc [2] a3 b2 [2] 9e }

  condition:
    any of them
}