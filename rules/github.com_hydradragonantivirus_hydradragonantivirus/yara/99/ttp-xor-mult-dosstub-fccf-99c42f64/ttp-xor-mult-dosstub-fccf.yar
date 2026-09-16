rule TTP_XOR_MULT_DOSStub_fccf {
  strings:
    $key_fccf = { a8 a7 [2] dc bf [2] 9b bd [2] dc ac [2] 92 a0 [2] 9e aa [2] 89 a1 [2] 92 ef [2] af }

  condition:
    any of them
}