rule TTP_XOR_WriteProcessMemory_3d35 {
  strings:
    $key_3d35 = { 6a 47 [2] 58 65 [2] 5e 50 [2] 70 50 [2] 4f 4c }

  condition:
    any of them
}