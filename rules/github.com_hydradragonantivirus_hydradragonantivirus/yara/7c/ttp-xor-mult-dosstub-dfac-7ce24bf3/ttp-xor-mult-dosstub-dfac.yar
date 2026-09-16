rule TTP_XOR_MULT_DOSStub_dfac {
  strings:
    $key_dfac = { 8b c4 [2] ff dc [2] b8 de [2] ff cf [2] b1 c3 [2] bd c9 [2] aa c2 [2] b1 8c [2] 8c }

  condition:
    any of them
}