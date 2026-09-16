rule TTP_XOR_MULT_DOSStub_bd5b {
  strings:
    $key_bd5b = { e9 33 [2] 9d 2b [2] da 29 [2] 9d 38 [2] d3 34 [2] df 3e [2] c8 35 [2] d3 7b [2] ee }

  condition:
    any of them
}