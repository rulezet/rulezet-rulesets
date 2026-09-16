rule TTP_XOR_MULT_DOSStub_bdfc {
  strings:
    $key_bdfc = { e9 94 [2] 9d 8c [2] da 8e [2] 9d 9f [2] d3 93 [2] df 99 [2] c8 92 [2] d3 dc [2] ee }

  condition:
    any of them
}