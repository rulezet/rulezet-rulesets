rule TTP_XOR_WriteProcessMemory_3602 {
  strings:
    $key_3602 = { 61 70 [2] 53 52 [2] 55 67 [2] 7b 67 [2] 44 7b }

  condition:
    any of them
}