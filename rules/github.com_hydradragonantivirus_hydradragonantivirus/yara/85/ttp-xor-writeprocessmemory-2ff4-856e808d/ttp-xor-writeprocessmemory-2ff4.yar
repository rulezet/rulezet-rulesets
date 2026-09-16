rule TTP_XOR_WriteProcessMemory_2ff4 {
  strings:
    $key_2ff4 = { 78 86 [2] 4a a4 [2] 4c 91 [2] 62 91 [2] 5d 8d }

  condition:
    any of them
}