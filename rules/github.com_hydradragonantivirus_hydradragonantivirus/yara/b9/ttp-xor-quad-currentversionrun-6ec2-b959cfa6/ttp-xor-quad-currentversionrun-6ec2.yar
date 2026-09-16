rule TTP_XOR_QUAD_CurrentVersionRun_6ec2 {
  strings:
    $key_6ec2 = { 3d ad [2] 19 a3 [2] 32 8f [2] 1c ad [2] 08 b6 [2] 07 ac [2] 19 b1 [2] 1b b0 [2] 00 b6 [2] 1c b1 [2] 00 9e }

  condition:
    any of them
}