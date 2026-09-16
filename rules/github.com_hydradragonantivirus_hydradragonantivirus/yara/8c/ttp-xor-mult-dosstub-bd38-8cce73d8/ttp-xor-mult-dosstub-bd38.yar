rule TTP_XOR_MULT_DOSStub_bd38 {
  strings:
    $key_bd38 = { e9 50 [2] 9d 48 [2] da 4a [2] 9d 5b [2] d3 57 [2] df 5d [2] c8 56 [2] d3 18 [2] ee }

  condition:
    any of them
}