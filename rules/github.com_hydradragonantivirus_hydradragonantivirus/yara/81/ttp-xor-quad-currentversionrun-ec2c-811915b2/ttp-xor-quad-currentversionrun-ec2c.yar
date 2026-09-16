rule TTP_XOR_QUAD_CurrentVersionRun_ec2c {
  strings:
    $key_ec2c = { bf 43 [2] 9b 4d [2] b0 61 [2] 9e 43 [2] 8a 58 [2] 85 42 [2] 9b 5f [2] 99 5e [2] 82 58 [2] 9e 5f [2] 82 70 }

  condition:
    any of them
}