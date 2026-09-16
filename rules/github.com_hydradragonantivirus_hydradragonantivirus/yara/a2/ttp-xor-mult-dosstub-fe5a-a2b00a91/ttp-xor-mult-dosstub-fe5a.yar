rule TTP_XOR_MULT_DOSStub_fe5a {
  strings:
    $key_fe5a = { aa 32 [2] de 2a [2] 99 28 [2] de 39 [2] 90 35 [2] 9c 3f [2] 8b 34 [2] 90 7a [2] ad }

  condition:
    any of them
}