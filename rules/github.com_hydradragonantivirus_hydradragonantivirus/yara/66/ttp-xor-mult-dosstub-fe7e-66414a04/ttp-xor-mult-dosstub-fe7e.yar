rule TTP_XOR_MULT_DOSStub_fe7e {
  strings:
    $key_fe7e = { aa 16 [2] de 0e [2] 99 0c [2] de 1d [2] 90 11 [2] 9c 1b [2] 8b 10 [2] 90 5e [2] ad }

  condition:
    any of them
}