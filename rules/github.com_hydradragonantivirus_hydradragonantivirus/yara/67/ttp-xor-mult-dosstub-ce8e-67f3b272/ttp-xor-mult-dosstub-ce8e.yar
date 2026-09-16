rule TTP_XOR_MULT_DOSStub_ce8e {
  strings:
    $key_ce8e = { 9a e6 [2] ee fe [2] a9 fc [2] ee ed [2] a0 e1 [2] ac eb [2] bb e0 [2] a0 ae [2] 9d }

  condition:
    any of them
}