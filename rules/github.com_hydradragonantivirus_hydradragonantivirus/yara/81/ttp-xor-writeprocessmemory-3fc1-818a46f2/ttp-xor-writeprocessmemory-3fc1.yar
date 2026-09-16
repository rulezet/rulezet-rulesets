rule TTP_XOR_WriteProcessMemory_3fc1 {
  strings:
    $key_3fc1 = { 68 b3 [2] 5a 91 [2] 5c a4 [2] 72 a4 [2] 4d b8 }

  condition:
    any of them
}