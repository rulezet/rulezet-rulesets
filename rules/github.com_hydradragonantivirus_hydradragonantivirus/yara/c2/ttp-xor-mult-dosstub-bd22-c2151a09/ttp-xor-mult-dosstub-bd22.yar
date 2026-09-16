rule TTP_XOR_MULT_DOSStub_bd22 {
  strings:
    $key_bd22 = { e9 4a [2] 9d 52 [2] da 50 [2] 9d 41 [2] d3 4d [2] df 47 [2] c8 4c [2] d3 02 [2] ee }

  condition:
    any of them
}