rule TTP_XOR_MULT_DOSStub_bdea {
  strings:
    $key_bdea = { e9 82 [2] 9d 9a [2] da 98 [2] 9d 89 [2] d3 85 [2] df 8f [2] c8 84 [2] d3 ca [2] ee }

  condition:
    any of them
}