rule TTP_XOR_WriteProcessMemory_5931 {
  strings:
    $key_5931 = { 0e 43 [2] 3c 61 [2] 3a 54 [2] 14 54 [2] 2b 48 }

  condition:
    any of them
}