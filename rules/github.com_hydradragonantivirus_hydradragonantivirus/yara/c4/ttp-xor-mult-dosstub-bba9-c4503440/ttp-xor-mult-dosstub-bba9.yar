rule TTP_XOR_MULT_DOSStub_bba9 {
  strings:
    $key_bba9 = { ef c1 [2] 9b d9 [2] dc db [2] 9b ca [2] d5 c6 [2] d9 cc [2] ce c7 [2] d5 89 [2] e8 }

  condition:
    any of them
}