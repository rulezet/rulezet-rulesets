rule TTP_XOR_MULT_DOSStub_bd6a {
  strings:
    $key_bd6a = { e9 02 [2] 9d 1a [2] da 18 [2] 9d 09 [2] d3 05 [2] df 0f [2] c8 04 [2] d3 4a [2] ee }

  condition:
    any of them
}