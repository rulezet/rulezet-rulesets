rule TTP_XOR_MULT_DOSStub_cedc {
  strings:
    $key_cedc = { 9a b4 [2] ee ac [2] a9 ae [2] ee bf [2] a0 b3 [2] ac b9 [2] bb b2 [2] a0 fc [2] 9d }

  condition:
    any of them
}