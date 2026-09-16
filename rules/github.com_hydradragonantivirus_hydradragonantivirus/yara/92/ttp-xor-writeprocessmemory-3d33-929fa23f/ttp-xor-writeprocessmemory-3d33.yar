rule TTP_XOR_WriteProcessMemory_3d33 {
  strings:
    $key_3d33 = { 6a 41 [2] 58 63 [2] 5e 56 [2] 70 56 [2] 4f 4a }

  condition:
    any of them
}