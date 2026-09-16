rule TTP_XOR_MULT_DOSStub_fe2f {
  strings:
    $key_fe2f = { aa 47 [2] de 5f [2] 99 5d [2] de 4c [2] 90 40 [2] 9c 4a [2] 8b 41 [2] 90 0f [2] ad }

  condition:
    any of them
}