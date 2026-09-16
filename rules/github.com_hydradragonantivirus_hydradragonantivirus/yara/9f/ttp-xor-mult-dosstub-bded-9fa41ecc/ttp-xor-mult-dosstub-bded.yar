rule TTP_XOR_MULT_DOSStub_bded {
  strings:
    $key_bded = { e9 85 [2] 9d 9d [2] da 9f [2] 9d 8e [2] d3 82 [2] df 88 [2] c8 83 [2] d3 cd [2] ee }

  condition:
    any of them
}