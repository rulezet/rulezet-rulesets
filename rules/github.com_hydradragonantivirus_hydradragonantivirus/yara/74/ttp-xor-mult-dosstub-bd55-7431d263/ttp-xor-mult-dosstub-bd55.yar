rule TTP_XOR_MULT_DOSStub_bd55 {
  strings:
    $key_bd55 = { e9 3d [2] 9d 25 [2] da 27 [2] 9d 36 [2] d3 3a [2] df 30 [2] c8 3b [2] d3 75 [2] ee }

  condition:
    any of them
}