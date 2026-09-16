rule TTP_XOR_MULT_DOSStub_dda4 {
  strings:
    $key_dda4 = { 89 cc [2] fd d4 [2] ba d6 [2] fd c7 [2] b3 cb [2] bf c1 [2] a8 ca [2] b3 84 [2] 8e }

  condition:
    any of them
}