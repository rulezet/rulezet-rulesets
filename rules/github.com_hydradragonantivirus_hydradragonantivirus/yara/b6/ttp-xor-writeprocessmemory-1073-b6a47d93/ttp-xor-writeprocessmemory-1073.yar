rule TTP_XOR_WriteProcessMemory_1073 {
  strings:
    $key_1073 = { 47 01 [2] 75 23 [2] 73 16 [2] 5d 16 [2] 62 0a }

  condition:
    any of them
}