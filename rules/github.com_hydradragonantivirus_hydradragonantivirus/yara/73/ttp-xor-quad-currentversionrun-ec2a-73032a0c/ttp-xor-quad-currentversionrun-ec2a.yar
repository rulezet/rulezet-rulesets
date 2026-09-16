rule TTP_XOR_QUAD_CurrentVersionRun_ec2a {
  strings:
    $key_ec2a = { bf 45 [2] 9b 4b [2] b0 67 [2] 9e 45 [2] 8a 5e [2] 85 44 [2] 9b 59 [2] 99 58 [2] 82 5e [2] 9e 59 [2] 82 76 }

  condition:
    any of them
}