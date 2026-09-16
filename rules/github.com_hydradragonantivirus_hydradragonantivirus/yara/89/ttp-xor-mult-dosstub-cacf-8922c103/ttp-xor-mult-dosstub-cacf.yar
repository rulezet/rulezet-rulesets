rule TTP_XOR_MULT_DOSStub_cacf {
  strings:
    $key_cacf = { 9e a7 [2] ea bf [2] ad bd [2] ea ac [2] a4 a0 [2] a8 aa [2] bf a1 [2] a4 ef [2] 99 }

  condition:
    any of them
}