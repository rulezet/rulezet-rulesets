rule TTP_XOR_MULT_DOSStub_8229 {
  strings:
    $key_8229 = { d6 41 [2] a2 59 [2] e5 5b [2] a2 4a [2] ec 46 [2] e0 4c [2] f7 47 [2] ec 09 [2] d1 }

  condition:
    any of them
}