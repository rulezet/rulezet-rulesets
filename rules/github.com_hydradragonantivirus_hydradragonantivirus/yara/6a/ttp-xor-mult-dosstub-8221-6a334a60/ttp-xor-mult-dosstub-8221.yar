rule TTP_XOR_MULT_DOSStub_8221 {
  strings:
    $key_8221 = { d6 49 [2] a2 51 [2] e5 53 [2] a2 42 [2] ec 4e [2] e0 44 [2] f7 4f [2] ec 01 [2] d1 }

  condition:
    any of them
}