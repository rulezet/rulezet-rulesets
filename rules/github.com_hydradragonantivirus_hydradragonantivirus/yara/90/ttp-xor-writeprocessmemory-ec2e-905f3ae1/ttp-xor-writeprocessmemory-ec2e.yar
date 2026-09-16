rule TTP_XOR_WriteProcessMemory_ec2e {
  strings:
    $key_ec2e = { bb 5c [2] 89 7e [2] 8f 4b [2] a1 4b [2] 9e 57 }

  condition:
    any of them
}