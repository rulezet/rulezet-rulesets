rule TTP_XOR_MULT_DOSStub_5fba {
  strings:
    $key_5fba = { 0b d2 [2] 7f ca [2] 38 c8 [2] 7f d9 [2] 31 d5 [2] 3d df [2] 2a d4 [2] 31 9a [2] 0c }

  condition:
    any of them
}