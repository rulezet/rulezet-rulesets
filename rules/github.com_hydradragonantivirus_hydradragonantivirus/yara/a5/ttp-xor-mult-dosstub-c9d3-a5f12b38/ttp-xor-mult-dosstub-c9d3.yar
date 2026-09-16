rule TTP_XOR_MULT_DOSStub_c9d3 {
  strings:
    $key_c9d3 = { 9d bb [2] e9 a3 [2] ae a1 [2] e9 b0 [2] a7 bc [2] ab b6 [2] bc bd [2] a7 f3 [2] 9a }

  condition:
    any of them
}