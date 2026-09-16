rule TTP_XOR_MULT_DOSStub_fe4c {
  strings:
    $key_fe4c = { aa 24 [2] de 3c [2] 99 3e [2] de 2f [2] 90 23 [2] 9c 29 [2] 8b 22 [2] 90 6c [2] ad }

  condition:
    any of them
}