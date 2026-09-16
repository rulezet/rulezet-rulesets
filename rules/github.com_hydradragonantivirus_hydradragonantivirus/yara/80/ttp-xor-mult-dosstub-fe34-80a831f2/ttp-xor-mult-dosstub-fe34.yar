rule TTP_XOR_MULT_DOSStub_fe34 {
  strings:
    $key_fe34 = { aa 5c [2] de 44 [2] 99 46 [2] de 57 [2] 90 5b [2] 9c 51 [2] 8b 5a [2] 90 14 [2] ad }

  condition:
    any of them
}