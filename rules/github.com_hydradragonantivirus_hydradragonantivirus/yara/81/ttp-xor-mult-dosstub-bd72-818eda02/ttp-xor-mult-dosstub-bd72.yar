rule TTP_XOR_MULT_DOSStub_bd72 {
  strings:
    $key_bd72 = { e9 1a [2] 9d 02 [2] da 00 [2] 9d 11 [2] d3 1d [2] df 17 [2] c8 1c [2] d3 52 [2] ee }

  condition:
    any of them
}