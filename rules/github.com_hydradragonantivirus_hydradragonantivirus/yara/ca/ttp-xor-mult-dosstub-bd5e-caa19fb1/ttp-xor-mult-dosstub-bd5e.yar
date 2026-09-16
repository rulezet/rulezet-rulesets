rule TTP_XOR_MULT_DOSStub_bd5e {
  strings:
    $key_bd5e = { e9 36 [2] 9d 2e [2] da 2c [2] 9d 3d [2] d3 31 [2] df 3b [2] c8 30 [2] d3 7e [2] ee }

  condition:
    any of them
}