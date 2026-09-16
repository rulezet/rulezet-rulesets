rule TTP_XOR_MULT_DOSStub_dfcf {
  strings:
    $key_dfcf = { 8b a7 [2] ff bf [2] b8 bd [2] ff ac [2] b1 a0 [2] bd aa [2] aa a1 [2] b1 ef [2] 8c }

  condition:
    any of them
}