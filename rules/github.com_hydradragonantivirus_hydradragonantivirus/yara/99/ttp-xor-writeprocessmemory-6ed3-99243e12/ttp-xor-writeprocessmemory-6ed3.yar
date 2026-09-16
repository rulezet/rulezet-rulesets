rule TTP_XOR_WriteProcessMemory_6ed3 {
  strings:
    $key_6ed3 = { 39 a1 [2] 0b 83 [2] 0d b6 [2] 23 b6 [2] 1c aa }

  condition:
    any of them
}