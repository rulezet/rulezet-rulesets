rule TTP_XOR_MULT_DOSStub_faac {
  strings:
    $key_faac = { ae c4 [2] da dc [2] 9d de [2] da cf [2] 94 c3 [2] 98 c9 [2] 8f c2 [2] 94 8c [2] a9 }

  condition:
    any of them
}