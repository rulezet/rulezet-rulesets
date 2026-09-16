rule TTP_XOR_MULT_DOSStub_bdcd {
  strings:
    $key_bdcd = { e9 a5 [2] 9d bd [2] da bf [2] 9d ae [2] d3 a2 [2] df a8 [2] c8 a3 [2] d3 ed [2] ee }

  condition:
    any of them
}