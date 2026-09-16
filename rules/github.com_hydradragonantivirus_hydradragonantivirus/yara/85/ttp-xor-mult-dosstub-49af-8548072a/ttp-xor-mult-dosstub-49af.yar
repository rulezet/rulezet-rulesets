rule TTP_XOR_MULT_DOSStub_49af {
  strings:
    $key_49af = { 1d c7 [2] 69 df [2] 2e dd [2] 69 cc [2] 27 c0 [2] 2b ca [2] 3c c1 [2] 27 8f [2] 1a }

  condition:
    any of them
}