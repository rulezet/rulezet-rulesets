rule TTP_XOR_MULT_DOSStub_bd4b {
  strings:
    $key_bd4b = { e9 23 [2] 9d 3b [2] da 39 [2] 9d 28 [2] d3 24 [2] df 2e [2] c8 25 [2] d3 6b [2] ee }

  condition:
    any of them
}