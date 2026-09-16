rule TTP_XOR_MULT_DOSStub_82ea {
  strings:
    $key_82ea = { d6 82 [2] a2 9a [2] e5 98 [2] a2 89 [2] ec 85 [2] e0 8f [2] f7 84 [2] ec ca [2] d1 }

  condition:
    any of them
}