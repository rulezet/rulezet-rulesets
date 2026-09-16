rule TTP_XOR_MULT_DOSStub_fe0e {
  strings:
    $key_fe0e = { aa 66 [2] de 7e [2] 99 7c [2] de 6d [2] 90 61 [2] 9c 6b [2] 8b 60 [2] 90 2e [2] ad }

  condition:
    any of them
}