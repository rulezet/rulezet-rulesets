rule TTP_XOR_WriteProcessMemory_ec2a {
  strings:
    $key_ec2a = { bb 58 [2] 89 7a [2] 8f 4f [2] a1 4f [2] 9e 53 }

  condition:
    any of them
}