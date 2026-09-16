rule TTP_XOR_WriteProcessMemory_3ff4 {
  strings:
    $key_3ff4 = { 68 86 [2] 5a a4 [2] 5c 91 [2] 72 91 [2] 4d 8d }

  condition:
    any of them
}