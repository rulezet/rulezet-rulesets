rule TTP_XOR_MULT_DOSStub_88a2 {
  strings:
    $key_88a2 = { dc ca [2] a8 d2 [2] ef d0 [2] a8 c1 [2] e6 cd [2] ea c7 [2] fd cc [2] e6 82 [2] db }

  condition:
    any of them
}