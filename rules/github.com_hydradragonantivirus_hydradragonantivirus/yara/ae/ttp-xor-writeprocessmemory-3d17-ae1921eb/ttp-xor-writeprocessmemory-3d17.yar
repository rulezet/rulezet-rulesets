rule TTP_XOR_WriteProcessMemory_3d17 {
  strings:
    $key_3d17 = { 6a 65 [2] 58 47 [2] 5e 72 [2] 70 72 [2] 4f 6e }

  condition:
    any of them
}