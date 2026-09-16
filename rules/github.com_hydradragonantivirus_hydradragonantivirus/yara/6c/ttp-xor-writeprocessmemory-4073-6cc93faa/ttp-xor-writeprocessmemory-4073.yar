rule TTP_XOR_WriteProcessMemory_4073 {
  strings:
    $key_4073 = { 17 01 [2] 25 23 [2] 23 16 [2] 0d 16 [2] 32 0a }

  condition:
    any of them
}