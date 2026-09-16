rule TTP_XOR_MULT_DOSStub_aea2 {
  strings:
    $key_aea2 = { fa ca [2] 8e d2 [2] c9 d0 [2] 8e c1 [2] c0 cd [2] cc c7 [2] db cc [2] c0 82 [2] fd }

  condition:
    any of them
}