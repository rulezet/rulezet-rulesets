rule TTP_XOR_MULT_DOSStub_bd53 {
  strings:
    $key_bd53 = { e9 3b [2] 9d 23 [2] da 21 [2] 9d 30 [2] d3 3c [2] df 36 [2] c8 3d [2] d3 73 [2] ee }

  condition:
    any of them
}