rule TTP_XOR_MULT_DOSStub_bd43 {
  strings:
    $key_bd43 = { e9 2b [2] 9d 33 [2] da 31 [2] 9d 20 [2] d3 2c [2] df 26 [2] c8 2d [2] d3 63 [2] ee }

  condition:
    any of them
}