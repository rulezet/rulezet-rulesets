rule TTP_XOR_MULT_DOSStub_bd21 {
  strings:
    $key_bd21 = { e9 49 [2] 9d 51 [2] da 53 [2] 9d 42 [2] d3 4e [2] df 44 [2] c8 4f [2] d3 01 [2] ee }

  condition:
    any of them
}