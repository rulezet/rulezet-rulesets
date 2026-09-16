rule TTP_XOR_MULT_DOSStub_822e {
  strings:
    $key_822e = { d6 46 [2] a2 5e [2] e5 5c [2] a2 4d [2] ec 41 [2] e0 4b [2] f7 40 [2] ec 0e [2] d1 }

  condition:
    any of them
}