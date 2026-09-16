rule TTP_XOR_MULT_DOSStub_bd5a {
  strings:
    $key_bd5a = { e9 32 [2] 9d 2a [2] da 28 [2] 9d 39 [2] d3 35 [2] df 3f [2] c8 34 [2] d3 7a [2] ee }

  condition:
    any of them
}