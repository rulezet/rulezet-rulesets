rule TTP_XOR_WriteProcessMemory_1fc1 {
  strings:
    $key_1fc1 = { 48 b3 [2] 7a 91 [2] 7c a4 [2] 52 a4 [2] 6d b8 }

  condition:
    any of them
}