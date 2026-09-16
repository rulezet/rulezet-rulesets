rule TTP_XOR_MULT_DOSStub_86ea {
  strings:
    $key_86ea = { d2 82 [2] a6 9a [2] e1 98 [2] a6 89 [2] e8 85 [2] e4 8f [2] f3 84 [2] e8 ca [2] d5 }

  condition:
    any of them
}