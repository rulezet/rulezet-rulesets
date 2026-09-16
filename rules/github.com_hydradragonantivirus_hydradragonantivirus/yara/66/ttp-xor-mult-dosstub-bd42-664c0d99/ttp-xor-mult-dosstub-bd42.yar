rule TTP_XOR_MULT_DOSStub_bd42 {
  strings:
    $key_bd42 = { e9 2a [2] 9d 32 [2] da 30 [2] 9d 21 [2] d3 2d [2] df 27 [2] c8 2c [2] d3 62 [2] ee }

  condition:
    any of them
}