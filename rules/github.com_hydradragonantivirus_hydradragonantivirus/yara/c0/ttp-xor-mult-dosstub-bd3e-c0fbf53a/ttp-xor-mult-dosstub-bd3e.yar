rule TTP_XOR_MULT_DOSStub_bd3e {
  strings:
    $key_bd3e = { e9 56 [2] 9d 4e [2] da 4c [2] 9d 5d [2] d3 51 [2] df 5b [2] c8 50 [2] d3 1e [2] ee }

  condition:
    any of them
}