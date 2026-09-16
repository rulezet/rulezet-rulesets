rule TTP_XOR_MULT_DOSStub_beac {
  strings:
    $key_beac = { ea c4 [2] 9e dc [2] d9 de [2] 9e cf [2] d0 c3 [2] dc c9 [2] cb c2 [2] d0 8c [2] ed }

  condition:
    any of them
}