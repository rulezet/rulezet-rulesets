rule TTP_XOR_WriteProcessMemory_2ac1 {
  strings:
    $key_2ac1 = { 7d b3 [2] 4f 91 [2] 49 a4 [2] 67 a4 [2] 58 b8 }

  condition:
    any of them
}