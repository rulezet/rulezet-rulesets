rule TTP_XOR_MULT_DOSStub_bd44 {
  strings:
    $key_bd44 = { e9 2c [2] 9d 34 [2] da 36 [2] 9d 27 [2] d3 2b [2] df 21 [2] c8 2a [2] d3 64 [2] ee }

  condition:
    any of them
}