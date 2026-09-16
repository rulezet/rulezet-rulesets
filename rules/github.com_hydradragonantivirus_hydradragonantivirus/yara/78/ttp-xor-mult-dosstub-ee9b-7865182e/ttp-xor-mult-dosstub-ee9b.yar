rule TTP_XOR_MULT_DOSStub_ee9b {
  strings:
    $key_ee9b = { ba f3 [2] ce eb [2] 89 e9 [2] ce f8 [2] 80 f4 [2] 8c fe [2] 9b f5 [2] 80 bb [2] bd }

  condition:
    any of them
}