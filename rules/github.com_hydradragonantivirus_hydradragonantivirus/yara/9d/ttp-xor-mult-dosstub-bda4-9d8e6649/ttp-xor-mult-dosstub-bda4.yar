rule TTP_XOR_MULT_DOSStub_bda4 {
  strings:
    $key_bda4 = { e9 cc [2] 9d d4 [2] da d6 [2] 9d c7 [2] d3 cb [2] df c1 [2] c8 ca [2] d3 84 [2] ee }

  condition:
    any of them
}