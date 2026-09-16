rule TTP_XOR_MULT_DOSStub_ea8d {
  strings:
    $key_ea8d = { be e5 [2] ca fd [2] 8d ff [2] ca ee [2] 84 e2 [2] 88 e8 [2] 9f e3 [2] 84 ad [2] b9 }

  condition:
    any of them
}