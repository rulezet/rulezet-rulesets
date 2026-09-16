rule TTP_XOR_MULT_DOSStub_fe23 {
  strings:
    $key_fe23 = { aa 4b [2] de 53 [2] 99 51 [2] de 40 [2] 90 4c [2] 9c 46 [2] 8b 4d [2] 90 03 [2] ad }

  condition:
    any of them
}