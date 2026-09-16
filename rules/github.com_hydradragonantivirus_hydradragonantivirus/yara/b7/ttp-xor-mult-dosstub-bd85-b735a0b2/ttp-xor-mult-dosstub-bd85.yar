rule TTP_XOR_MULT_DOSStub_bd85 {
  strings:
    $key_bd85 = { e9 ed [2] 9d f5 [2] da f7 [2] 9d e6 [2] d3 ea [2] df e0 [2] c8 eb [2] d3 a5 [2] ee }

  condition:
    any of them
}