rule TTP_XOR_MULT_DOSStub_bd68 {
  strings:
    $key_bd68 = { e9 00 [2] 9d 18 [2] da 1a [2] 9d 0b [2] d3 07 [2] df 0d [2] c8 06 [2] d3 48 [2] ee }

  condition:
    any of them
}