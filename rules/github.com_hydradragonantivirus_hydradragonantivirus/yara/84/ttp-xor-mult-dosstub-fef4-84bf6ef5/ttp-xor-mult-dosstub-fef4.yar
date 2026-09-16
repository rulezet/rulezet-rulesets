rule TTP_XOR_MULT_DOSStub_fef4 {
  strings:
    $key_fef4 = { aa 9c [2] de 84 [2] 99 86 [2] de 97 [2] 90 9b [2] 9c 91 [2] 8b 9a [2] 90 d4 [2] ad }

  condition:
    any of them
}