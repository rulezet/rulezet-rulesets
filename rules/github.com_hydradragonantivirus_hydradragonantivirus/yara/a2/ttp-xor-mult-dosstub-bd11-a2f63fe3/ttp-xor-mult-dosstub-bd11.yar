rule TTP_XOR_MULT_DOSStub_bd11 {
  strings:
    $key_bd11 = { e9 79 [2] 9d 61 [2] da 63 [2] 9d 72 [2] d3 7e [2] df 74 [2] c8 7f [2] d3 31 [2] ee }

  condition:
    any of them
}