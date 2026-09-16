rule TTP_XOR_MULT_DOSStub_3fba {
  strings:
    $key_3fba = { 6b d2 [2] 1f ca [2] 58 c8 [2] 1f d9 [2] 51 d5 [2] 5d df [2] 4a d4 [2] 51 9a [2] 6c }

  condition:
    any of them
}