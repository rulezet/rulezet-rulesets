rule TTP_XOR_MULT_DOSStub_bd27 {
  strings:
    $key_bd27 = { e9 4f [2] 9d 57 [2] da 55 [2] 9d 44 [2] d3 48 [2] df 42 [2] c8 49 [2] d3 07 [2] ee }

  condition:
    any of them
}