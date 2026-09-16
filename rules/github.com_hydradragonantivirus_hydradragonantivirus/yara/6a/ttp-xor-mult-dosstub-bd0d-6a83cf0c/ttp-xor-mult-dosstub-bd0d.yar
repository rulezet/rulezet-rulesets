rule TTP_XOR_MULT_DOSStub_bd0d {
  strings:
    $key_bd0d = { e9 65 [2] 9d 7d [2] da 7f [2] 9d 6e [2] d3 62 [2] df 68 [2] c8 63 [2] d3 2d [2] ee }

  condition:
    any of them
}