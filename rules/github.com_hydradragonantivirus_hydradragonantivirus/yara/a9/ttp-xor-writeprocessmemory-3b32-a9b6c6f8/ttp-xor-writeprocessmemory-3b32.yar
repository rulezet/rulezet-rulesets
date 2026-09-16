rule TTP_XOR_WriteProcessMemory_3b32 {
  strings:
    $key_3b32 = { 6c 40 [2] 5e 62 [2] 58 57 [2] 76 57 [2] 49 4b }

  condition:
    any of them
}