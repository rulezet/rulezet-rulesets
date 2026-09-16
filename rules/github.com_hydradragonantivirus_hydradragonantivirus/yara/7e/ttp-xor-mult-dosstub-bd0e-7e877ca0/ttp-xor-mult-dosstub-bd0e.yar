rule TTP_XOR_MULT_DOSStub_bd0e {
  strings:
    $key_bd0e = { e9 66 [2] 9d 7e [2] da 7c [2] 9d 6d [2] d3 61 [2] df 6b [2] c8 60 [2] d3 2e [2] ee }

  condition:
    any of them
}