rule TTP_XOR_MULT_DOSStub_4ec2 {
  strings:
    $key_4ec2 = { 1a aa [2] 6e b2 [2] 29 b0 [2] 6e a1 [2] 20 ad [2] 2c a7 [2] 3b ac [2] 20 e2 [2] 1d }

  condition:
    any of them
}