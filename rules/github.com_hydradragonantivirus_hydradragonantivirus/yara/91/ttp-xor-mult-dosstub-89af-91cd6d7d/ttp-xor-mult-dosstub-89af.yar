rule TTP_XOR_MULT_DOSStub_89af {
  strings:
    $key_89af = { dd c7 [2] a9 df [2] ee dd [2] a9 cc [2] e7 c0 [2] eb ca [2] fc c1 [2] e7 8f [2] da }

  condition:
    any of them
}