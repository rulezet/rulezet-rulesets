rule TTP_XOR_MULT_DOSStub_bd1a {
  strings:
    $key_bd1a = { e9 72 [2] 9d 6a [2] da 68 [2] 9d 79 [2] d3 75 [2] df 7f [2] c8 74 [2] d3 3a [2] ee }

  condition:
    any of them
}