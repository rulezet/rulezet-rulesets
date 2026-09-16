rule TTP_XOR_MULT_DOSStub_ddac {
  strings:
    $key_ddac = { 89 c4 [2] fd dc [2] ba de [2] fd cf [2] b3 c3 [2] bf c9 [2] a8 c2 [2] b3 8c [2] 8e }

  condition:
    any of them
}