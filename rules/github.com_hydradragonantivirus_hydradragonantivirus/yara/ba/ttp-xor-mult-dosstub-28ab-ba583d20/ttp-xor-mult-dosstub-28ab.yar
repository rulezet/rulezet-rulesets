rule TTP_XOR_MULT_DOSStub_28ab {
  strings:
    $key_28ab = { 7c c3 [2] 08 db [2] 4f d9 [2] 08 c8 [2] 46 c4 [2] 4a ce [2] 5d c5 [2] 46 8b [2] 7b }

  condition:
    any of them
}