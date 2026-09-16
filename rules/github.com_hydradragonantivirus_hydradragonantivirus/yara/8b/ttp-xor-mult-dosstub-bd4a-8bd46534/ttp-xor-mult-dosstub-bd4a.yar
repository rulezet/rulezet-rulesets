rule TTP_XOR_MULT_DOSStub_bd4a {
  strings:
    $key_bd4a = { e9 22 [2] 9d 3a [2] da 38 [2] 9d 29 [2] d3 25 [2] df 2f [2] c8 24 [2] d3 6a [2] ee }

  condition:
    any of them
}