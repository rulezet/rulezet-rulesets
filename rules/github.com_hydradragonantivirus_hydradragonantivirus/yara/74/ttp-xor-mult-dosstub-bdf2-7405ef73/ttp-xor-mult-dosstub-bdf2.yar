rule TTP_XOR_MULT_DOSStub_bdf2 {
  strings:
    $key_bdf2 = { e9 9a [2] 9d 82 [2] da 80 [2] 9d 91 [2] d3 9d [2] df 97 [2] c8 9c [2] d3 d2 [2] ee }

  condition:
    any of them
}