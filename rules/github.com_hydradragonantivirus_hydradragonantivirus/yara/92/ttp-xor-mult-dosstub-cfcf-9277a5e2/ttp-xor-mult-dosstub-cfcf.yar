rule TTP_XOR_MULT_DOSStub_cfcf {
  strings:
    $key_cfcf = { 9b a7 [2] ef bf [2] a8 bd [2] ef ac [2] a1 a0 [2] ad aa [2] ba a1 [2] a1 ef [2] 9c }

  condition:
    any of them
}