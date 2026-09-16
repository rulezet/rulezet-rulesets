rule TTP_XOR_MULT_DOSStub_bd70 {
  strings:
    $key_bd70 = { e9 18 [2] 9d 00 [2] da 02 [2] 9d 13 [2] d3 1f [2] df 15 [2] c8 1e [2] d3 50 [2] ee }

  condition:
    any of them
}