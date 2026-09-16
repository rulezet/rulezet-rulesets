rule TTP_XOR_WriteProcessMemory_1e35 {
  strings:
    $key_1e35 = { 49 47 [2] 7b 65 [2] 7d 50 [2] 53 50 [2] 6c 4c }

  condition:
    any of them
}