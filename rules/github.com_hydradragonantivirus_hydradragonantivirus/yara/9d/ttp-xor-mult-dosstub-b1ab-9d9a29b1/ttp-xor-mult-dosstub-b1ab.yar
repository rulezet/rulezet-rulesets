rule TTP_XOR_MULT_DOSStub_b1ab {
  strings:
    $key_b1ab = { e5 c3 [2] 91 db [2] d6 d9 [2] 91 c8 [2] df c4 [2] d3 ce [2] c4 c5 [2] df 8b [2] e2 }

  condition:
    any of them
}