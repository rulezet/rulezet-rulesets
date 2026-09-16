rule TTP_XOR_MULT_DOSStub_bd08 {
  strings:
    $key_bd08 = { e9 60 [2] 9d 78 [2] da 7a [2] 9d 6b [2] d3 67 [2] df 6d [2] c8 66 [2] d3 28 [2] ee }

  condition:
    any of them
}