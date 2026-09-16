rule TTP_XOR_MULT_DOSStub_fe6a {
  strings:
    $key_fe6a = { aa 02 [2] de 1a [2] 99 18 [2] de 09 [2] 90 05 [2] 9c 0f [2] 8b 04 [2] 90 4a [2] ad }

  condition:
    any of them
}