rule TTP_XOR_MULT_DOSStub_fef2 {
  strings:
    $key_fef2 = { aa 9a [2] de 82 [2] 99 80 [2] de 91 [2] 90 9d [2] 9c 97 [2] 8b 9c [2] 90 d2 [2] ad }

  condition:
    any of them
}