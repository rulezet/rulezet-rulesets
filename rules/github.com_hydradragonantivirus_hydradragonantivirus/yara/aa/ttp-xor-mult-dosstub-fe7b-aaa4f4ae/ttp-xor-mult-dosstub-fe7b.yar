rule TTP_XOR_MULT_DOSStub_fe7b {
  strings:
    $key_fe7b = { aa 13 [2] de 0b [2] 99 09 [2] de 18 [2] 90 14 [2] 9c 1e [2] 8b 15 [2] 90 5b [2] ad }

  condition:
    any of them
}