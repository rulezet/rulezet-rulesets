rule TTP_XOR_MULT_DOSStub_bdf3 {
  strings:
    $key_bdf3 = { e9 9b [2] 9d 83 [2] da 81 [2] 9d 90 [2] d3 9c [2] df 96 [2] c8 9d [2] d3 d3 [2] ee }

  condition:
    any of them
}