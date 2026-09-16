rule TTP_XOR_MULT_DOSStub_bd4f {
  strings:
    $key_bd4f = { e9 27 [2] 9d 3f [2] da 3d [2] 9d 2c [2] d3 20 [2] df 2a [2] c8 21 [2] d3 6f [2] ee }

  condition:
    any of them
}