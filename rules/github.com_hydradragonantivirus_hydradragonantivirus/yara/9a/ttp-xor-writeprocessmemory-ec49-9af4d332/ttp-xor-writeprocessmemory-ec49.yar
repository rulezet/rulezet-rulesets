rule TTP_XOR_WriteProcessMemory_ec49 {
  strings:
    $key_ec49 = { bb 3b [2] 89 19 [2] 8f 2c [2] a1 2c [2] 9e 30 }

  condition:
    any of them
}