rule TTP_XOR_MULT_DOSStub_bd29 {
  strings:
    $key_bd29 = { e9 41 [2] 9d 59 [2] da 5b [2] 9d 4a [2] d3 46 [2] df 4c [2] c8 47 [2] d3 09 [2] ee }

  condition:
    any of them
}