rule TTP_XOR_MULT_DOSStub_fe4b {
  strings:
    $key_fe4b = { aa 23 [2] de 3b [2] 99 39 [2] de 28 [2] 90 24 [2] 9c 2e [2] 8b 25 [2] 90 6b [2] ad }

  condition:
    any of them
}