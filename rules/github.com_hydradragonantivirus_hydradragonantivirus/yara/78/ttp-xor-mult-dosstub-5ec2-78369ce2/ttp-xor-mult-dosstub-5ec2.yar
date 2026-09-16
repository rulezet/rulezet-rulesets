rule TTP_XOR_MULT_DOSStub_5ec2 {
  strings:
    $key_5ec2 = { 0a aa [2] 7e b2 [2] 39 b0 [2] 7e a1 [2] 30 ad [2] 3c a7 [2] 2b ac [2] 30 e2 [2] 0d }

  condition:
    any of them
}