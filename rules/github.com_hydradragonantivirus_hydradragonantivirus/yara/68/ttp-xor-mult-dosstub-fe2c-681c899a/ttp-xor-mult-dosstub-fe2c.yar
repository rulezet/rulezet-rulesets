rule TTP_XOR_MULT_DOSStub_fe2c {
  strings:
    $key_fe2c = { aa 44 [2] de 5c [2] 99 5e [2] de 4f [2] 90 43 [2] 9c 49 [2] 8b 42 [2] 90 0c [2] ad }

  condition:
    any of them
}