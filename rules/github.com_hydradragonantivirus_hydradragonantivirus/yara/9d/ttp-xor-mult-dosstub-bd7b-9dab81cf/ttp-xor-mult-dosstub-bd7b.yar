rule TTP_XOR_MULT_DOSStub_bd7b {
  strings:
    $key_bd7b = { e9 13 [2] 9d 0b [2] da 09 [2] 9d 18 [2] d3 14 [2] df 1e [2] c8 15 [2] d3 5b [2] ee }

  condition:
    any of them
}