rule TTP_XOR_MULT_DOSStub_fefe {
  strings:
    $key_fefe = { aa 96 [2] de 8e [2] 99 8c [2] de 9d [2] 90 91 [2] 9c 9b [2] 8b 90 [2] 90 de [2] ad }

  condition:
    any of them
}