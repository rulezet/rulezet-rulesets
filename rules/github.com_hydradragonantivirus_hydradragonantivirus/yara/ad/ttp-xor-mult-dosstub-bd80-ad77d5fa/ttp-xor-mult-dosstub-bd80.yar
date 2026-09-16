rule TTP_XOR_MULT_DOSStub_bd80 {
  strings:
    $key_bd80 = { e9 e8 [2] 9d f0 [2] da f2 [2] 9d e3 [2] d3 ef [2] df e5 [2] c8 ee [2] d3 a0 [2] ee }

  condition:
    any of them
}