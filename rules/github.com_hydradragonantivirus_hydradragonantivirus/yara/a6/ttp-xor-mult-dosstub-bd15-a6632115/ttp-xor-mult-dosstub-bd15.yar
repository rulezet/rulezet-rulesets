rule TTP_XOR_MULT_DOSStub_bd15 {
  strings:
    $key_bd15 = { e9 7d [2] 9d 65 [2] da 67 [2] 9d 76 [2] d3 7a [2] df 70 [2] c8 7b [2] d3 35 [2] ee }

  condition:
    any of them
}