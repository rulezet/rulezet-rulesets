rule TTP_XOR_MULT_DOSStub_fdba {
  strings:
    $key_fdba = { a9 d2 [2] dd ca [2] 9a c8 [2] dd d9 [2] 93 d5 [2] 9f df [2] 88 d4 [2] 93 9a [2] ae }

  condition:
    any of them
}