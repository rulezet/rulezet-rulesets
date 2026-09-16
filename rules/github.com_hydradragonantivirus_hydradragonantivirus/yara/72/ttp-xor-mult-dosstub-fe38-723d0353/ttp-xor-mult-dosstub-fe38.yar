rule TTP_XOR_MULT_DOSStub_fe38 {
  strings:
    $key_fe38 = { aa 50 [2] de 48 [2] 99 4a [2] de 5b [2] 90 57 [2] 9c 5d [2] 8b 56 [2] 90 18 [2] ad }

  condition:
    any of them
}