rule TTP_XOR_WriteProcessMemory_4ff4 {
  strings:
    $key_4ff4 = { 18 86 [2] 2a a4 [2] 2c 91 [2] 02 91 [2] 3d 8d }

  condition:
    any of them
}