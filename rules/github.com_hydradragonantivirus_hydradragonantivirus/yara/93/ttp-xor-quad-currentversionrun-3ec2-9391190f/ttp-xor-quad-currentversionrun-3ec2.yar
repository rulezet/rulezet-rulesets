rule TTP_XOR_QUAD_CurrentVersionRun_3ec2 {
  strings:
    $key_3ec2 = { 6d ad [2] 49 a3 [2] 62 8f [2] 4c ad [2] 58 b6 [2] 57 ac [2] 49 b1 [2] 4b b0 [2] 50 b6 [2] 4c b1 [2] 50 9e }

  condition:
    any of them
}