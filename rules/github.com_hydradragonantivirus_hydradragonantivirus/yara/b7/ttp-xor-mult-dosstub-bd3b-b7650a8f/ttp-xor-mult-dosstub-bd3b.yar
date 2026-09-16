rule TTP_XOR_MULT_DOSStub_bd3b {
  strings:
    $key_bd3b = { e9 53 [2] 9d 4b [2] da 49 [2] 9d 58 [2] d3 54 [2] df 5e [2] c8 55 [2] d3 1b [2] ee }

  condition:
    any of them
}