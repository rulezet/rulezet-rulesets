rule TTP_XOR_MULT_DOSStub_fe0c {
  strings:
    $key_fe0c = { aa 64 [2] de 7c [2] 99 7e [2] de 6f [2] 90 63 [2] 9c 69 [2] 8b 62 [2] 90 2c [2] ad }

  condition:
    any of them
}