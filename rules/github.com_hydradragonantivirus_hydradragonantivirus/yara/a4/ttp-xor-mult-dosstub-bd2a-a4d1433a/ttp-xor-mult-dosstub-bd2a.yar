rule TTP_XOR_MULT_DOSStub_bd2a {
  strings:
    $key_bd2a = { e9 42 [2] 9d 5a [2] da 58 [2] 9d 49 [2] d3 45 [2] df 4f [2] c8 44 [2] d3 0a [2] ee }

  condition:
    any of them
}