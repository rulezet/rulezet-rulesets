rule TTP_XOR_MULT_DOSStub_ded3 {
  strings:
    $key_ded3 = { 8a bb [2] fe a3 [2] b9 a1 [2] fe b0 [2] b0 bc [2] bc b6 [2] ab bd [2] b0 f3 [2] 8d }

  condition:
    any of them
}