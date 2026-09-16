rule TTP_XOR_MULT_DOSStub_ee85 {
  strings:
    $key_ee85 = { ba ed [2] ce f5 [2] 89 f7 [2] ce e6 [2] 80 ea [2] 8c e0 [2] 9b eb [2] 80 a5 [2] bd }

  condition:
    any of them
}