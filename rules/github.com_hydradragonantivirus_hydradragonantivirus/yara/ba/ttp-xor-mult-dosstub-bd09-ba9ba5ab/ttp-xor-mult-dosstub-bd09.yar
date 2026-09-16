rule TTP_XOR_MULT_DOSStub_bd09 {
  strings:
    $key_bd09 = { e9 61 [2] 9d 79 [2] da 7b [2] 9d 6a [2] d3 66 [2] df 6c [2] c8 67 [2] d3 29 [2] ee }

  condition:
    any of them
}