rule TTP_XOR_MULT_DOSStub_fe29 {
  strings:
    $key_fe29 = { aa 41 [2] de 59 [2] 99 5b [2] de 4a [2] 90 46 [2] 9c 4c [2] 8b 47 [2] 90 09 [2] ad }

  condition:
    any of them
}