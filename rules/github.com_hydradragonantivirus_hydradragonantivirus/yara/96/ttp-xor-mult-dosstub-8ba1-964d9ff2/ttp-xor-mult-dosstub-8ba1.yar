rule TTP_XOR_MULT_DOSStub_8ba1 {
  strings:
    $key_8ba1 = { df c9 [2] ab d1 [2] ec d3 [2] ab c2 [2] e5 ce [2] e9 c4 [2] fe cf [2] e5 81 [2] d8 }

  condition:
    any of them
}