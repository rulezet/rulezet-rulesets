rule TTP_XOR_MULT_DOSStub_bd01 {
  strings:
    $key_bd01 = { e9 69 [2] 9d 71 [2] da 73 [2] 9d 62 [2] d3 6e [2] df 64 [2] c8 6f [2] d3 21 [2] ee }

  condition:
    any of them
}