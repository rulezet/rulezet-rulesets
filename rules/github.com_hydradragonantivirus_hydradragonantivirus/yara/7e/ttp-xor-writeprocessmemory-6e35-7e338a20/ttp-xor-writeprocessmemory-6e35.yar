rule TTP_XOR_WriteProcessMemory_6e35 {
  strings:
    $key_6e35 = { 39 47 [2] 0b 65 [2] 0d 50 [2] 23 50 [2] 1c 4c }

  condition:
    any of them
}