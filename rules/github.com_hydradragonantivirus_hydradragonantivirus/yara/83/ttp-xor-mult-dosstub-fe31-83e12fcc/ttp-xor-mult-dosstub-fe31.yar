rule TTP_XOR_MULT_DOSStub_fe31 {
  strings:
    $key_fe31 = { aa 59 [2] de 41 [2] 99 43 [2] de 52 [2] 90 5e [2] 9c 54 [2] 8b 5f [2] 90 11 [2] ad }

  condition:
    any of them
}