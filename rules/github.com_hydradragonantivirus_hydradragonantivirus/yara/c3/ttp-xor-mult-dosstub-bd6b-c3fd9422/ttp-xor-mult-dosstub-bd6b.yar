rule TTP_XOR_MULT_DOSStub_bd6b {
  strings:
    $key_bd6b = { e9 03 [2] 9d 1b [2] da 19 [2] 9d 08 [2] d3 04 [2] df 0e [2] c8 05 [2] d3 4b [2] ee }

  condition:
    any of them
}