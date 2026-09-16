rule TTP_XOR_QUAD_CurrentVersionRun_54ed {
  strings:
    $key_54ed = { 07 82 [2] 23 8c [2] 08 a0 [2] 26 82 [2] 32 99 [2] 3d 83 [2] 23 9e [2] 21 9f [2] 3a 99 [2] 26 9e [2] 3a b1 }

  condition:
    any of them
}