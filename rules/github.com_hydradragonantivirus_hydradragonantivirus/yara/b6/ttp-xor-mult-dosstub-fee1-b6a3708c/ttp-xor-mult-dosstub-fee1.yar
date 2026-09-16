rule TTP_XOR_MULT_DOSStub_fee1 {
  strings:
    $key_fee1 = { aa 89 [2] de 91 [2] 99 93 [2] de 82 [2] 90 8e [2] 9c 84 [2] 8b 8f [2] 90 c1 [2] ad }

  condition:
    any of them
}