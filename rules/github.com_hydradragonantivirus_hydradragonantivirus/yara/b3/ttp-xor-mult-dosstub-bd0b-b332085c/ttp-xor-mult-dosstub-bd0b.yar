rule TTP_XOR_MULT_DOSStub_bd0b {
  strings:
    $key_bd0b = { e9 63 [2] 9d 7b [2] da 79 [2] 9d 68 [2] d3 64 [2] df 6e [2] c8 65 [2] d3 2b [2] ee }

  condition:
    any of them
}