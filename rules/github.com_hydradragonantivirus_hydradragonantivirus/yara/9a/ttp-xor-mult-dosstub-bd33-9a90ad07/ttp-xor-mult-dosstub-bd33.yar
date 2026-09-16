rule TTP_XOR_MULT_DOSStub_bd33 {
  strings:
    $key_bd33 = { e9 5b [2] 9d 43 [2] da 41 [2] 9d 50 [2] d3 5c [2] df 56 [2] c8 5d [2] d3 13 [2] ee }

  condition:
    any of them
}