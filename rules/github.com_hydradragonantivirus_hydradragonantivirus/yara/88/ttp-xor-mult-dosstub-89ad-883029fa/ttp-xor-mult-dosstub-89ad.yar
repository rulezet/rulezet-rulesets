rule TTP_XOR_MULT_DOSStub_89ad {
  strings:
    $key_89ad = { dd c5 [2] a9 dd [2] ee df [2] a9 ce [2] e7 c2 [2] eb c8 [2] fc c3 [2] e7 8d [2] da }

  condition:
    any of them
}