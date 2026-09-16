rule TTP_XOR_MULT_DOSStub_95ea {
  strings:
    $key_95ea = { c1 82 [2] b5 9a [2] f2 98 [2] b5 89 [2] fb 85 [2] f7 8f [2] e0 84 [2] fb ca [2] c6 }

  condition:
    any of them
}