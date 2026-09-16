rule TTP_XOR_QUAD_CurrentVersionRun_7ec2 {
  strings:
    $key_7ec2 = { 2d ad [2] 09 a3 [2] 22 8f [2] 0c ad [2] 18 b6 [2] 17 ac [2] 09 b1 [2] 0b b0 [2] 10 b6 [2] 0c b1 [2] 10 9e }

  condition:
    any of them
}