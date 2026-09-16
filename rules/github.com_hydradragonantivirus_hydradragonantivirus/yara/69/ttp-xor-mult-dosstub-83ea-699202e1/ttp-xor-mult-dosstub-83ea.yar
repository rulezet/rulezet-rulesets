rule TTP_XOR_MULT_DOSStub_83ea {
  strings:
    $key_83ea = { d7 82 [2] a3 9a [2] e4 98 [2] a3 89 [2] ed 85 [2] e1 8f [2] f6 84 [2] ed ca [2] d0 }

  condition:
    any of them
}