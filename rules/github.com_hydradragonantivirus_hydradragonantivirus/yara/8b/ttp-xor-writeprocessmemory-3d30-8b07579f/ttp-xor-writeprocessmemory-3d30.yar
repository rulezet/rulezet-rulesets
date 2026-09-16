rule TTP_XOR_WriteProcessMemory_3d30 {
  strings:
    $key_3d30 = { 6a 42 [2] 58 60 [2] 5e 55 [2] 70 55 [2] 4f 49 }

  condition:
    any of them
}