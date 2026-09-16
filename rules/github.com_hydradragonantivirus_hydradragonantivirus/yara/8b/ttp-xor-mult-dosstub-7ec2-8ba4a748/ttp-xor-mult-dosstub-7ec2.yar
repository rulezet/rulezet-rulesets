rule TTP_XOR_MULT_DOSStub_7ec2 {
  strings:
    $key_7ec2 = { 2a aa [2] 5e b2 [2] 19 b0 [2] 5e a1 [2] 10 ad [2] 1c a7 [2] 0b ac [2] 10 e2 [2] 2d }

  condition:
    any of them
}