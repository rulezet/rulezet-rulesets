rule TTP_XOR_MULT_DOSStub_bd77 {
  strings:
    $key_bd77 = { e9 1f [2] 9d 07 [2] da 05 [2] 9d 14 [2] d3 18 [2] df 12 [2] c8 19 [2] d3 57 [2] ee }

  condition:
    any of them
}