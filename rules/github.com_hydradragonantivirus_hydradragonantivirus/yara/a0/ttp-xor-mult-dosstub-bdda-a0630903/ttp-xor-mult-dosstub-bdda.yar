rule TTP_XOR_MULT_DOSStub_bdda {
  strings:
    $key_bdda = { e9 b2 [2] 9d aa [2] da a8 [2] 9d b9 [2] d3 b5 [2] df bf [2] c8 b4 [2] d3 fa [2] ee }

  condition:
    any of them
}