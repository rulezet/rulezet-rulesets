rule TTP_XOR_WriteProcessMemory_3d47 {
  strings:
    $key_3d47 = { 6a 35 [2] 58 17 [2] 5e 22 [2] 70 22 [2] 4f 3e }

  condition:
    any of them
}