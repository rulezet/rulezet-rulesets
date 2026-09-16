rule TTP_XOR_MULT_DOSStub_fe5f {
  strings:
    $key_fe5f = { aa 37 [2] de 2f [2] 99 2d [2] de 3c [2] 90 30 [2] 9c 3a [2] 8b 31 [2] 90 7f [2] ad }

  condition:
    any of them
}