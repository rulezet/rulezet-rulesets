rule TTP_XOR_WriteProcessMemory_4031 {
  strings:
    $key_4031 = { 17 43 [2] 25 61 [2] 23 54 [2] 0d 54 [2] 32 48 }

  condition:
    any of them
}