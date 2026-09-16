rule TTP_XOR_WriteProcessMemory_ec40 {
  strings:
    $key_ec40 = { bb 32 [2] 89 10 [2] 8f 25 [2] a1 25 [2] 9e 39 }

  condition:
    any of them
}