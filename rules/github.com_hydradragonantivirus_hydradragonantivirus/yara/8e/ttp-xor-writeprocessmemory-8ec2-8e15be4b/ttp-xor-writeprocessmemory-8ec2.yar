rule TTP_XOR_WriteProcessMemory_8ec2 {
  strings:
    $key_8ec2 = { d9 b0 [2] eb 92 [2] ed a7 [2] c3 a7 [2] fc bb }

  condition:
    any of them
}