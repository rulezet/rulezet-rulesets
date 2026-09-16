rule TTP_XOR_MULT_DOSStub_bd67 {
  strings:
    $key_bd67 = { e9 0f [2] 9d 17 [2] da 15 [2] 9d 04 [2] d3 08 [2] df 02 [2] c8 09 [2] d3 47 [2] ee }

  condition:
    any of them
}