rule TTP_XOR_MULT_DOSStub_bd62 {
  strings:
    $key_bd62 = { e9 0a [2] 9d 12 [2] da 10 [2] 9d 01 [2] d3 0d [2] df 07 [2] c8 0c [2] d3 42 [2] ee }

  condition:
    any of them
}