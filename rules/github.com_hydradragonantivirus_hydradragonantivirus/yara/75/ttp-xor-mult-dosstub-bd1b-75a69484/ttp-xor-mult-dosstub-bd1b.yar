rule TTP_XOR_MULT_DOSStub_bd1b {
  strings:
    $key_bd1b = { e9 73 [2] 9d 6b [2] da 69 [2] 9d 78 [2] d3 74 [2] df 7e [2] c8 75 [2] d3 3b [2] ee }

  condition:
    any of them
}