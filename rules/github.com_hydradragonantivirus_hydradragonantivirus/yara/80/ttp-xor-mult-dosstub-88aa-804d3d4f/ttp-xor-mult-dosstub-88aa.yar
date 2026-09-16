rule TTP_XOR_MULT_DOSStub_88aa {
  strings:
    $key_88aa = { dc c2 [2] a8 da [2] ef d8 [2] a8 c9 [2] e6 c5 [2] ea cf [2] fd c4 [2] e6 8a [2] db }

  condition:
    any of them
}