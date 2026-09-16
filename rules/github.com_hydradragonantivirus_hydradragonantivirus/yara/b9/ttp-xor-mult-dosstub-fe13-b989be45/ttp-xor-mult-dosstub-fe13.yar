rule TTP_XOR_MULT_DOSStub_fe13 {
  strings:
    $key_fe13 = { aa 7b [2] de 63 [2] 99 61 [2] de 70 [2] 90 7c [2] 9c 76 [2] 8b 7d [2] 90 33 [2] ad }

  condition:
    any of them
}