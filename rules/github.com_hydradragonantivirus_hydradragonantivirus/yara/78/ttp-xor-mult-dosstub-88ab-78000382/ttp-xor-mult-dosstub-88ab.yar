rule TTP_XOR_MULT_DOSStub_88ab {
  strings:
    $key_88ab = { dc c3 [2] a8 db [2] ef d9 [2] a8 c8 [2] e6 c4 [2] ea ce [2] fd c5 [2] e6 8b [2] db }

  condition:
    any of them
}