rule TTP_XOR_WriteProcessMemory_ec01 {
  strings:
    $key_ec01 = { bb 73 [2] 89 51 [2] 8f 64 [2] a1 64 [2] 9e 78 }

  condition:
    any of them
}