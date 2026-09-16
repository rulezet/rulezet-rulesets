rule TTP_XOR_MULT_DOSStub_cd95 {
  strings:
    $key_cd95 = { 99 fd [2] ed e5 [2] aa e7 [2] ed f6 [2] a3 fa [2] af f0 [2] b8 fb [2] a3 b5 [2] 9e }

  condition:
    any of them
}