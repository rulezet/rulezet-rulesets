rule TTP_XOR_MULT_DOSStub_bd79 {
  strings:
    $key_bd79 = { e9 11 [2] 9d 09 [2] da 0b [2] 9d 1a [2] d3 16 [2] df 1c [2] c8 17 [2] d3 59 [2] ee }

  condition:
    any of them
}