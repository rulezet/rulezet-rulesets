rule TTP_XOR_MULT_DOSStub_94ea {
  strings:
    $key_94ea = { c0 82 [2] b4 9a [2] f3 98 [2] b4 89 [2] fa 85 [2] f6 8f [2] e1 84 [2] fa ca [2] c7 }

  condition:
    any of them
}