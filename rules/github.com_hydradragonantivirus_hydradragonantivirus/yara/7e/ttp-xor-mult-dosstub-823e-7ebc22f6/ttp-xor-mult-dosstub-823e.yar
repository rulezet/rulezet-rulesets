rule TTP_XOR_MULT_DOSStub_823e {
  strings:
    $key_823e = { d6 56 [2] a2 4e [2] e5 4c [2] a2 5d [2] ec 51 [2] e0 5b [2] f7 50 [2] ec 1e [2] d1 }

  condition:
    any of them
}