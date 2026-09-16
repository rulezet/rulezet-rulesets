rule TTP_XOR_MULT_DOSStub_2ec2 {
  strings:
    $key_2ec2 = { 7a aa [2] 0e b2 [2] 49 b0 [2] 0e a1 [2] 40 ad [2] 4c a7 [2] 5b ac [2] 40 e2 [2] 7d }

  condition:
    any of them
}