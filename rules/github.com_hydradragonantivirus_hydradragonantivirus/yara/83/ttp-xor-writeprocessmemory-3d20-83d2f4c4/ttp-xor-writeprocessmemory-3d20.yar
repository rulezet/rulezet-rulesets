rule TTP_XOR_WriteProcessMemory_3d20 {
  strings:
    $key_3d20 = { 6a 52 [2] 58 70 [2] 5e 45 [2] 70 45 [2] 4f 59 }

  condition:
    any of them
}