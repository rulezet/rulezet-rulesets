rule TTP_XOR_WriteProcessMemory_588d {
  strings:
    $key_588d = { 0f ff [2] 3d dd [2] 3b e8 [2] 15 e8 [2] 2a f4 }

  condition:
    any of them
}