rule TTP_XOR_WriteProcessMemory_ec2c {
  strings:
    $key_ec2c = { bb 5e [2] 89 7c [2] 8f 49 [2] a1 49 [2] 9e 55 }

  condition:
    any of them
}