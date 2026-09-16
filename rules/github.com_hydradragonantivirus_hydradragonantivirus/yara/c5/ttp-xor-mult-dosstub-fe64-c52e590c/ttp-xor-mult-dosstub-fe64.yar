rule TTP_XOR_MULT_DOSStub_fe64 {
  strings:
    $key_fe64 = { aa 0c [2] de 14 [2] 99 16 [2] de 07 [2] 90 0b [2] 9c 01 [2] 8b 0a [2] 90 44 [2] ad }

  condition:
    any of them
}