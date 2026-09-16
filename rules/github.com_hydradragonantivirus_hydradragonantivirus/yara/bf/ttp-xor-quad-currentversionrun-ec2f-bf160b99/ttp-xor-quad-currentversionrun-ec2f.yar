rule TTP_XOR_QUAD_CurrentVersionRun_ec2f {
  strings:
    $key_ec2f = { bf 40 [2] 9b 4e [2] b0 62 [2] 9e 40 [2] 8a 5b [2] 85 41 [2] 9b 5c [2] 99 5d [2] 82 5b [2] 9e 5c [2] 82 73 }

  condition:
    any of them
}