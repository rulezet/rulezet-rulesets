rule TTP_XOR_MULT_DOSStub_bdf5 {
  strings:
    $key_bdf5 = { e9 9d [2] 9d 85 [2] da 87 [2] 9d 96 [2] d3 9a [2] df 90 [2] c8 9b [2] d3 d5 [2] ee }

  condition:
    any of them
}