rule TTP_XOR_WriteProcessMemory_2fc1 {
  strings:
    $key_2fc1 = { 78 b3 [2] 4a 91 [2] 4c a4 [2] 62 a4 [2] 5d b8 }

  condition:
    any of them
}