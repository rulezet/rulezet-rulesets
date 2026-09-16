rule TTP_XOR_MULT_DOSStub_abac {
  strings:
    $key_abac = { ff c4 [2] 8b dc [2] cc de [2] 8b cf [2] c5 c3 [2] c9 c9 [2] de c2 [2] c5 8c [2] f8 }

  condition:
    any of them
}