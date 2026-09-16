rule TTP_XOR_MULT_DOSStub_bd0f {
  strings:
    $key_bd0f = { e9 67 [2] 9d 7f [2] da 7d [2] 9d 6c [2] d3 60 [2] df 6a [2] c8 61 [2] d3 2f [2] ee }

  condition:
    any of them
}