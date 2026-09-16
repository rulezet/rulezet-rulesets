rule TTP_XOR_MULT_DOSStub_bd2d {
  strings:
    $key_bd2d = { e9 45 [2] 9d 5d [2] da 5f [2] 9d 4e [2] d3 42 [2] df 48 [2] c8 43 [2] d3 0d [2] ee }

  condition:
    any of them
}