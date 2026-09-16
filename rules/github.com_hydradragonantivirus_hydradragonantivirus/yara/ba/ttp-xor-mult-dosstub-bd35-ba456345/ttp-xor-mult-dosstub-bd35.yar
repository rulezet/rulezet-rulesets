rule TTP_XOR_MULT_DOSStub_bd35 {
  strings:
    $key_bd35 = { e9 5d [2] 9d 45 [2] da 47 [2] 9d 56 [2] d3 5a [2] df 50 [2] c8 5b [2] d3 15 [2] ee }

  condition:
    any of them
}