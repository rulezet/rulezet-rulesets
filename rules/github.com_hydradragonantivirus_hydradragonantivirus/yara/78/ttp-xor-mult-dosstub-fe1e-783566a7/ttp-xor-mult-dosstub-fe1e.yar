rule TTP_XOR_MULT_DOSStub_fe1e {
  strings:
    $key_fe1e = { aa 76 [2] de 6e [2] 99 6c [2] de 7d [2] 90 71 [2] 9c 7b [2] 8b 70 [2] 90 3e [2] ad }

  condition:
    any of them
}