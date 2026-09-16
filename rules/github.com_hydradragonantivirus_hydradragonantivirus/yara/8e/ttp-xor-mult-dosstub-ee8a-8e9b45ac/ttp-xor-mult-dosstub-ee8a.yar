rule TTP_XOR_MULT_DOSStub_ee8a {
  strings:
    $key_ee8a = { ba e2 [2] ce fa [2] 89 f8 [2] ce e9 [2] 80 e5 [2] 8c ef [2] 9b e4 [2] 80 aa [2] bd }

  condition:
    any of them
}