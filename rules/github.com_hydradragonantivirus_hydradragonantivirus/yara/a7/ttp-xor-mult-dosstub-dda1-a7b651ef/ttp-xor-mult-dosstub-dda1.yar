rule TTP_XOR_MULT_DOSStub_dda1 {
  strings:
    $key_dda1 = { 89 c9 [2] fd d1 [2] ba d3 [2] fd c2 [2] b3 ce [2] bf c4 [2] a8 cf [2] b3 81 [2] 8e }

  condition:
    any of them
}