rule TTP_XOR_MULT_DOSStub_0ec2 {
  strings:
    $key_0ec2 = { 5a aa [2] 2e b2 [2] 69 b0 [2] 2e a1 [2] 60 ad [2] 6c a7 [2] 7b ac [2] 60 e2 [2] 5d }

  condition:
    any of them
}