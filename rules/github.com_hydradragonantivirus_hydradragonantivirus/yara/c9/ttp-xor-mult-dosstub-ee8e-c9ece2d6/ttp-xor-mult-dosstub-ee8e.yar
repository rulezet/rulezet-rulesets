rule TTP_XOR_MULT_DOSStub_ee8e {
  strings:
    $key_ee8e = { ba e6 [2] ce fe [2] 89 fc [2] ce ed [2] 80 e1 [2] 8c eb [2] 9b e0 [2] 80 ae [2] bd }

  condition:
    any of them
}