rule TTP_XOR_MULT_DOSStub_feff {
  strings:
    $key_feff = { aa 97 [2] de 8f [2] 99 8d [2] de 9c [2] 90 90 [2] 9c 9a [2] 8b 91 [2] 90 df [2] ad }

  condition:
    any of them
}