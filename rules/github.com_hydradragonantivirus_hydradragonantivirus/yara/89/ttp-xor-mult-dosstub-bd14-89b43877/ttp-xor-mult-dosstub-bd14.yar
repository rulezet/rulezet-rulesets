rule TTP_XOR_MULT_DOSStub_bd14 {
  strings:
    $key_bd14 = { e9 7c [2] 9d 64 [2] da 66 [2] 9d 77 [2] d3 7b [2] df 71 [2] c8 7a [2] d3 34 [2] ee }

  condition:
    any of them
}