rule TTP_XOR_MULT_DOSStub_fdaf {
  strings:
    $key_fdaf = { a9 c7 [2] dd df [2] 9a dd [2] dd cc [2] 93 c0 [2] 9f ca [2] 88 c1 [2] 93 8f [2] ae }

  condition:
    any of them
}