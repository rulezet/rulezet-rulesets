rule TTP_XOR_MULT_DOSStub_c8d3 {
  strings:
    $key_c8d3 = { 9c bb [2] e8 a3 [2] af a1 [2] e8 b0 [2] a6 bc [2] aa b6 [2] bd bd [2] a6 f3 [2] 9b }

  condition:
    any of them
}