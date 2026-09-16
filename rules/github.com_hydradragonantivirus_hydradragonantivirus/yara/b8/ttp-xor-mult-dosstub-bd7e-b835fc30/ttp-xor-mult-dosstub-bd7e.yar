rule TTP_XOR_MULT_DOSStub_bd7e {
  strings:
    $key_bd7e = { e9 16 [2] 9d 0e [2] da 0c [2] 9d 1d [2] d3 11 [2] df 1b [2] c8 10 [2] d3 5e [2] ee }

  condition:
    any of them
}