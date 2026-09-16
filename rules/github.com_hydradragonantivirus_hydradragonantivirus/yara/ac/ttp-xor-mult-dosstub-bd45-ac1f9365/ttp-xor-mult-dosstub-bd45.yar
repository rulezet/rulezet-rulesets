rule TTP_XOR_MULT_DOSStub_bd45 {
  strings:
    $key_bd45 = { e9 2d [2] 9d 35 [2] da 37 [2] 9d 26 [2] d3 2a [2] df 20 [2] c8 2b [2] d3 65 [2] ee }

  condition:
    any of them
}