rule TTP_XOR_MULT_DOSStub_6fba {
  strings:
    $key_6fba = { 3b d2 [2] 4f ca [2] 08 c8 [2] 4f d9 [2] 01 d5 [2] 0d df [2] 1a d4 [2] 01 9a [2] 3c }

  condition:
    any of them
}