rule TTP_XOR_MULT_DOSStub_fef0 {
  strings:
    $key_fef0 = { aa 98 [2] de 80 [2] 99 82 [2] de 93 [2] 90 9f [2] 9c 95 [2] 8b 9e [2] 90 d0 [2] ad }

  condition:
    any of them
}