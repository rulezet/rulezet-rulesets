rule TTP_XOR_WriteProcessMemory_6ef2 {
  strings:
    $key_6ef2 = { 39 80 [2] 0b a2 [2] 0d 97 [2] 23 97 [2] 1c 8b }

  condition:
    any of them
}