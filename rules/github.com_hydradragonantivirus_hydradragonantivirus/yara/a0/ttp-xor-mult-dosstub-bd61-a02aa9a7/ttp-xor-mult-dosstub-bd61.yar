rule TTP_XOR_MULT_DOSStub_bd61 {
  strings:
    $key_bd61 = { e9 09 [2] 9d 11 [2] da 13 [2] 9d 02 [2] d3 0e [2] df 04 [2] c8 0f [2] d3 41 [2] ee }

  condition:
    any of them
}