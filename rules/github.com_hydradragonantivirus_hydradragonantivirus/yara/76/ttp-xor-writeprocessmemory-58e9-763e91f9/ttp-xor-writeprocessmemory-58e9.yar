rule TTP_XOR_WriteProcessMemory_58e9 {
  strings:
    $key_58e9 = { 0f 9b [2] 3d b9 [2] 3b 8c [2] 15 8c [2] 2a 90 }

  condition:
    any of them
}