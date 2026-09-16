rule TTP_XOR_MULT_DOSStub_822d {
  strings:
    $key_822d = { d6 45 [2] a2 5d [2] e5 5f [2] a2 4e [2] ec 42 [2] e0 48 [2] f7 43 [2] ec 0d [2] d1 }

  condition:
    any of them
}