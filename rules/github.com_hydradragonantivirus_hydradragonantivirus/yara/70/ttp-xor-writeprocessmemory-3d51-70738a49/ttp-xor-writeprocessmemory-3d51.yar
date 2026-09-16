rule TTP_XOR_WriteProcessMemory_3d51 {
  strings:
    $key_3d51 = { 6a 23 [2] 58 01 [2] 5e 34 [2] 70 34 [2] 4f 28 }

  condition:
    any of them
}