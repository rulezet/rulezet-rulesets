rule TTP_XOR_WriteProcessMemory_6ff4 {
  strings:
    $key_6ff4 = { 38 86 [2] 0a a4 [2] 0c 91 [2] 22 91 [2] 1d 8d }

  condition:
    any of them
}