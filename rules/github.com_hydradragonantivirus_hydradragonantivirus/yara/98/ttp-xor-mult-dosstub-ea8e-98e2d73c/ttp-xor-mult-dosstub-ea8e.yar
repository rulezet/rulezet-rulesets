rule TTP_XOR_MULT_DOSStub_ea8e {
  strings:
    $key_ea8e = { be e6 [2] ca fe [2] 8d fc [2] ca ed [2] 84 e1 [2] 88 eb [2] 9f e0 [2] 84 ae [2] b9 }

  condition:
    any of them
}