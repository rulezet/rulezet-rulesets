rule TTP_XOR_WriteProcessMemory_3d15 {
  strings:
    $key_3d15 = { 6a 67 [2] 58 45 [2] 5e 70 [2] 70 70 [2] 4f 6c }

  condition:
    any of them
}