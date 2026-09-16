rule TTP_XOR_MULT_DOSStub_826e {
  strings:
    $key_826e = { d6 06 [2] a2 1e [2] e5 1c [2] a2 0d [2] ec 01 [2] e0 0b [2] f7 00 [2] ec 4e [2] d1 }

  condition:
    any of them
}