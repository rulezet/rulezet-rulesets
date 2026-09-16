rule TTP_XOR_MULT_DOSStub_bd7a {
  strings:
    $key_bd7a = { e9 12 [2] 9d 0a [2] da 08 [2] 9d 19 [2] d3 15 [2] df 1f [2] c8 14 [2] d3 5a [2] ee }

  condition:
    any of them
}