rule TTP_XOR_WriteProcessMemory_6ec2 {
  strings:
    $key_6ec2 = { 39 b0 [2] 0b 92 [2] 0d a7 [2] 23 a7 [2] 1c bb }

  condition:
    any of them
}