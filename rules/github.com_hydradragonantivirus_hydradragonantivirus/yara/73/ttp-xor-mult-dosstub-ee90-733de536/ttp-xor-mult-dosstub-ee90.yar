rule TTP_XOR_MULT_DOSStub_ee90 {
  strings:
    $key_ee90 = { ba f8 [2] ce e0 [2] 89 e2 [2] ce f3 [2] 80 ff [2] 8c f5 [2] 9b fe [2] 80 b0 [2] bd }

  condition:
    any of them
}