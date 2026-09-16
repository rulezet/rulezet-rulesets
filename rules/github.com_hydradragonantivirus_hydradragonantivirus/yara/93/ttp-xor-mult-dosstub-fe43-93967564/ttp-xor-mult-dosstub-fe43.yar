rule TTP_XOR_MULT_DOSStub_fe43 {
  strings:
    $key_fe43 = { aa 2b [2] de 33 [2] 99 31 [2] de 20 [2] 90 2c [2] 9c 26 [2] 8b 2d [2] 90 63 [2] ad }

  condition:
    any of them
}