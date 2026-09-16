rule TTP_XOR_MULT_DOSStub_fe33 {
  strings:
    $key_fe33 = { aa 5b [2] de 43 [2] 99 41 [2] de 50 [2] 90 5c [2] 9c 56 [2] 8b 5d [2] 90 13 [2] ad }

  condition:
    any of them
}