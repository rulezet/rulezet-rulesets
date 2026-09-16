rule TTP_XOR_MULT_DOSStub_4fba {
  strings:
    $key_4fba = { 1b d2 [2] 6f ca [2] 28 c8 [2] 6f d9 [2] 21 d5 [2] 2d df [2] 3a d4 [2] 21 9a [2] 1c }

  condition:
    any of them
}