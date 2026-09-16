rule TTP_XOR_MULT_DOSStub_fbde {
  strings:
    $key_fbde = { af b6 [2] db ae [2] 9c ac [2] db bd [2] 95 b1 [2] 99 bb [2] 8e b0 [2] 95 fe [2] a8 }

  condition:
    any of them
}