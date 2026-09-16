rule TTP_XOR_WriteProcessMemory_3620 {
  strings:
    $key_3620 = { 61 52 [2] 53 70 [2] 55 45 [2] 7b 45 [2] 44 59 }

  condition:
    any of them
}