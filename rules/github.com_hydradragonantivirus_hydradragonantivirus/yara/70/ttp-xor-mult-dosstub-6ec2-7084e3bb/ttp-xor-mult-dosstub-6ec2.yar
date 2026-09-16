rule TTP_XOR_MULT_DOSStub_6ec2 {
  strings:
    $key_6ec2 = { 3a aa [2] 4e b2 [2] 09 b0 [2] 4e a1 [2] 00 ad [2] 0c a7 [2] 1b ac [2] 00 e2 [2] 3d }

  condition:
    any of them
}