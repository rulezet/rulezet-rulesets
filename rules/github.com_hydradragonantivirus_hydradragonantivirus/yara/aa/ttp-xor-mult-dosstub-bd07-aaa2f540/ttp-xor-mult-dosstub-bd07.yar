rule TTP_XOR_MULT_DOSStub_bd07 {
  strings:
    $key_bd07 = { e9 6f [2] 9d 77 [2] da 75 [2] 9d 64 [2] d3 68 [2] df 62 [2] c8 69 [2] d3 27 [2] ee }

  condition:
    any of them
}