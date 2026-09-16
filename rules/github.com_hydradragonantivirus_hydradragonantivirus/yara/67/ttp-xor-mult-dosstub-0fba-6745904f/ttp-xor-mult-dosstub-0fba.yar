rule TTP_XOR_MULT_DOSStub_0fba {
  strings:
    $key_0fba = { 5b d2 [2] 2f ca [2] 68 c8 [2] 2f d9 [2] 61 d5 [2] 6d df [2] 7a d4 [2] 61 9a [2] 5c }

  condition:
    any of them
}