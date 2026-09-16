rule TTP_XOR_MULT_DOSStub_edac {
  strings:
    $key_edac = { b9 c4 [2] cd dc [2] 8a de [2] cd cf [2] 83 c3 [2] 8f c9 [2] 98 c2 [2] 83 8c [2] be }

  condition:
    any of them
}