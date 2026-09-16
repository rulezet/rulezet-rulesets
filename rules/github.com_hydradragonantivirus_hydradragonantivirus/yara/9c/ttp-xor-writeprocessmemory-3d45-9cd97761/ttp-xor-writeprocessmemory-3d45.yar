rule TTP_XOR_WriteProcessMemory_3d45 {
  strings:
    $key_3d45 = { 6a 37 [2] 58 15 [2] 5e 20 [2] 70 20 [2] 4f 3c }

  condition:
    any of them
}