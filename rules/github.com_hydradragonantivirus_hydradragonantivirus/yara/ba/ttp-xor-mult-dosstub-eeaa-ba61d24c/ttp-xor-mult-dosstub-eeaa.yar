rule TTP_XOR_MULT_DOSStub_eeaa {
  strings:
    $key_eeaa = { ba c2 [2] ce da [2] 89 d8 [2] ce c9 [2] 80 c5 [2] 8c cf [2] 9b c4 [2] 80 8a [2] bd }

  condition:
    any of them
}