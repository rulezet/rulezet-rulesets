rule TTP_XOR_MULT_DOSStub_bd0a {
  strings:
    $key_bd0a = { e9 62 [2] 9d 7a [2] da 78 [2] 9d 69 [2] d3 65 [2] df 6f [2] c8 64 [2] d3 2a [2] ee }

  condition:
    any of them
}