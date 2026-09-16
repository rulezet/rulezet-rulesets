rule TTP_XOR_MULT_DOSStub_fe19 {
  strings:
    $key_fe19 = { aa 71 [2] de 69 [2] 99 6b [2] de 7a [2] 90 76 [2] 9c 7c [2] 8b 77 [2] 90 39 [2] ad }

  condition:
    any of them
}