rule TTP_XOR_MULT_DOSStub_bd16 {
  strings:
    $key_bd16 = { e9 7e [2] 9d 66 [2] da 64 [2] 9d 75 [2] d3 79 [2] df 73 [2] c8 78 [2] d3 36 [2] ee }

  condition:
    any of them
}