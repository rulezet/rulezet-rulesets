rule TTP_XOR_WriteProcessMemory_3613 {
  strings:
    $key_3613 = { 61 61 [2] 53 43 [2] 55 76 [2] 7b 76 [2] 44 6a }

  condition:
    any of them
}