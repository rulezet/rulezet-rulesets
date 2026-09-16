rule TTP_XOR_MULT_DOSStub_bd10 {
  strings:
    $key_bd10 = { e9 78 [2] 9d 60 [2] da 62 [2] 9d 73 [2] d3 7f [2] df 75 [2] c8 7e [2] d3 30 [2] ee }

  condition:
    any of them
}