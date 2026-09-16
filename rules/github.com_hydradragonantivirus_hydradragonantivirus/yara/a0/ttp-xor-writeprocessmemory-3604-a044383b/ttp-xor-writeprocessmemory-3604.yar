rule TTP_XOR_WriteProcessMemory_3604 {
  strings:
    $key_3604 = { 61 76 [2] 53 54 [2] 55 61 [2] 7b 61 [2] 44 7d }

  condition:
    any of them
}