rule TTP_XOR_MULT_DOSStub_bd32 {
  strings:
    $key_bd32 = { e9 5a [2] 9d 42 [2] da 40 [2] 9d 51 [2] d3 5d [2] df 57 [2] c8 5c [2] d3 12 [2] ee }

  condition:
    any of them
}