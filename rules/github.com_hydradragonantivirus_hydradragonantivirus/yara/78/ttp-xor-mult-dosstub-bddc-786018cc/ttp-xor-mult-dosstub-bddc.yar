rule TTP_XOR_MULT_DOSStub_bddc {
  strings:
    $key_bddc = { e9 b4 [2] 9d ac [2] da ae [2] 9d bf [2] d3 b3 [2] df b9 [2] c8 b2 [2] d3 fc [2] ee }

  condition:
    any of them
}