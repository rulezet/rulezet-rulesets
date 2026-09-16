rule TTP_XOR_MULT_DOSStub_bde3 {
  strings:
    $key_bde3 = { e9 8b [2] 9d 93 [2] da 91 [2] 9d 80 [2] d3 8c [2] df 86 [2] c8 8d [2] d3 c3 [2] ee }

  condition:
    any of them
}