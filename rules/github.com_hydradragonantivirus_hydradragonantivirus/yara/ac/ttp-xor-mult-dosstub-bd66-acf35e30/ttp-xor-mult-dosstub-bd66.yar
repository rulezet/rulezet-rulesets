rule TTP_XOR_MULT_DOSStub_bd66 {
  strings:
    $key_bd66 = { e9 0e [2] 9d 16 [2] da 14 [2] 9d 05 [2] d3 09 [2] df 03 [2] c8 08 [2] d3 46 [2] ee }

  condition:
    any of them
}