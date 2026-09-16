rule TTP_XOR_MULT_DOSStub_92ea {
  strings:
    $key_92ea = { c6 82 [2] b2 9a [2] f5 98 [2] b2 89 [2] fc 85 [2] f0 8f [2] e7 84 [2] fc ca [2] c1 }

  condition:
    any of them
}