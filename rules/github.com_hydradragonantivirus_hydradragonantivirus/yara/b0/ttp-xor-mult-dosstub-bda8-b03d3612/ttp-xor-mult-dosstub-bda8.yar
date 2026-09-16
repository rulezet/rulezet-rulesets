rule TTP_XOR_MULT_DOSStub_bda8 {
  strings:
    $key_bda8 = { e9 c0 [2] 9d d8 [2] da da [2] 9d cb [2] d3 c7 [2] df cd [2] c8 c6 [2] d3 88 [2] ee }

  condition:
    any of them
}