rule TTP_XOR_MULT_DOSStub_bd6e {
  strings:
    $key_bd6e = { e9 06 [2] 9d 1e [2] da 1c [2] 9d 0d [2] d3 01 [2] df 0b [2] c8 00 [2] d3 4e [2] ee }

  condition:
    any of them
}